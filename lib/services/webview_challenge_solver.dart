// Cross-platform DDoS-challenge solver.
//
// Anna's Archive is protected by DDoS-Guard. Its clearance cookies are HttpOnly
// AND bound to the browser context, so extracting them and replaying through Dio
// never works (that was the alpha's approach and it loops 403 forever). Instead
// we let a real browser engine pass the challenge and capture the fully rendered
// page HTML:
//
//   - Android/iOS: InAppBrowser opens a visible browser so the user can
//     complete any verification that requires interaction.
//   - Linux/Windows/macOS: desktop_webview_window opens a visible window (the
//     challenge usually auto-passes within seconds).
//
// Captured HTML is stored in ChallengeHtmlCache keyed by the request URL, so a
// retry ("Try Again") or another mirror attempt can parse it directly.

// Dart imports:
import 'dart:async';
import 'dart:convert';

// Package imports:
import 'package:desktop_webview_window/desktop_webview_window.dart'
    as desktop_webview;
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

// Project imports:
import 'package:openlib/services/challenge_html_cache.dart';
import 'package:openlib/services/logger.dart';
import 'package:openlib/services/platform_utils.dart';

class WebviewChallengeSolver {
  WebviewChallengeSolver._();

  static final AppLogger _logger = AppLogger();

  /// Android/iOS use flutter_inappwebview; desktop uses desktop_webview_window.
  static bool get isSupported =>
      PlatformUtils.isMobile || PlatformUtils.isDesktop;

  /// Escape hatch for tests and headless environments: when false,
  /// fetchHtmlAfterChallenge returns null immediately instead of opening
  /// a desktop window. Tests set this to false.
  static bool guiEnabled = true;

  /// Returns true when the given page looks like an unfinished DDoS protection
  /// challenge (DDoS-Guard or Cloudflare) instead of real content.
  static bool isChallengePage({
    required String title,
    required String bodySnippet,
  }) {
    final t = title.toLowerCase();
    final b = bodySnippet.toLowerCase();
    const titleMarkers = [
      'ddos-guard',
      'just a moment',
      'attention required',
      'checking your browser',
    ];
    const bodyMarkers = [
      'ddos-guard/js-challenge',
      'check.ddos-guard.net',
      'ddg-l10n-title',
      'cf-turnstile',
      'challenge-platform',
      'cf-browser-verification',
    ];
    return titleMarkers.any(t.contains) || bodyMarkers.any(b.contains);
  }

  /// Solves the challenge for [url] and returns the fully rendered page HTML,
  /// or null if the challenge could not be cleared within [timeout].
  ///
  /// Desktop opens a visible window (default 3 min); mobile opens a visible
  /// InAppBrowser (default 60 s) so the user can complete verification.
  /// The result is also stored in ChallengeHtmlCache.
  static Future<String?> fetchHtmlAfterChallenge(
    String url, {
    Duration? timeout,
  }) async {
    if (!isSupported || !guiEnabled) return null;

    final effectiveTimeout =
        timeout ??
        (PlatformUtils.isMobile
            ? const Duration(seconds: 60)
            : const Duration(minutes: 3));

    final html = PlatformUtils.isMobile
        ? await _solveVisibleMobile(url, effectiveTimeout)
        : await _solveDesktopWindow(url, effectiveTimeout);

    if (html != null) {
      ChallengeHtmlCache.store(url, html);
    }
    return html;
  }

  // ------------------------------------------------------------------
  // MOBILE: Visible InAppBrowser
  // ------------------------------------------------------------------

  static Future<String?> _solveVisibleMobile(
    String url,
    Duration timeout,
  ) async {
    try {
      final completer = Completer<String?>();

      final browser = _ChallengeBrowser(completer: completer, logger: _logger);

      await browser.openUrlRequest(
        urlRequest: URLRequest(url: WebUri(url)),
        settings: InAppBrowserClassSettings(
          browserSettings: InAppBrowserSettings(
            hideUrlBar: false,
            hideToolbarTop: false,
          ),
          webViewSettings: InAppWebViewSettings(
            javaScriptEnabled: true,
            javaScriptCanOpenWindowsAutomatically: true,
            supportZoom: true,
            incognito: false,
            clearCache: false,
          ),
        ),
      );

      final result = await completer.future.timeout(
        timeout,
        onTimeout: () => null,
      );

      try {
        await browser.close();
      } catch (_) {}

      return result;
    } catch (e, st) {
      _logger.error(
        'Visible mobile challenge solver failed',
        tag: 'ChallengeSolver',
        error: e,
        stackTrace: st,
      );
      return null;
    }
  }

  // ------------------------------------------------------------------
  // DESKTOP: visible desktop_webview_window
  // ------------------------------------------------------------------

  static Future<String?> _solveDesktopWindow(
    String url,
    Duration timeout,
  ) async {
    desktop_webview.Webview? webview;
    var closedByUser = false;
    try {
      webview = await desktop_webview.WebviewWindow.create(
        configuration: const desktop_webview.CreateConfiguration(
          windowHeight: 700,
          windowWidth: 1000,
          title: "Verifying access...",
        ),
      );
      webview.onClose.then((_) => closedByUser = true);
      webview.launch(url);

      final deadline = DateTime.now().add(timeout);
      var titleOkPolls = 0;
      while (DateTime.now().isBefore(deadline)) {
        await Future.delayed(const Duration(milliseconds: 1500));
        if (closedByUser) {
          _logger.info(
            'Challenge webview closed by user',
            tag: 'ChallengeSolver',
          );
          return null;
        }

        final title = await _js(webview, "document.title") ?? '';
        final bodySnippet =
            await _js(
              webview,
              "(document.body ? document.body.innerHTML.slice(0, 3000) : '')",
            ) ??
            '';

        if (title.isEmpty && bodySnippet.isEmpty) continue;

        if (isChallengePage(title: title, bodySnippet: bodySnippet)) {
          titleOkPolls = 0;
          _logger.debug(
            'Challenge still active',
            tag: 'ChallengeSolver',
            metadata: {'title': title.isEmpty ? '(none)' : title},
          );
          continue;
        }

        final readyState = await _js(webview, "document.readyState") ?? '';
        if (readyState != 'complete') {
          titleOkPolls++;
          _logger.debug(
            'Page rendering, waiting for readyState=complete',
            tag: 'ChallengeSolver',
            metadata: {'readyState': readyState, 'polls': titleOkPolls},
          );
          if (titleOkPolls < 10) continue;
        }

        final html = await _js(webview, "document.documentElement.outerHTML");
        if (html != null && html.isNotEmpty) {
          _logger.info(
            'Challenge solved, captured page HTML',
            tag: 'ChallengeSolver',
            metadata: {'length': html.length, 'title': title},
          );
          return html;
        }
      }
      _logger.warning('Challenge solver timed out', tag: 'ChallengeSolver');
      return null;
    } catch (e, st) {
      _logger.error(
        'Desktop challenge solver failed',
        tag: 'ChallengeSolver',
        error: e,
        stackTrace: st,
      );
      return null;
    } finally {
      // Closing programmatically crashed GTK in earlier versions; the user
      // closes the window manually.
      webview = null;
    }
  }

  // ------------------------------------------------------------------
  // SHARED HELPERS
  // ------------------------------------------------------------------

  /// Captures outerHTML once the document is complete and settled.
  static Future<String?> _captureHtml(dynamic controllerOrWebview) async {
    final ready = await _js(controllerOrWebview, "document.readyState") ?? '';
    if (ready != 'complete') return null;
    // Settle delay so late XHR content lands in the DOM.
    await Future.delayed(const Duration(milliseconds: 2000));
    final html = await _js(
      controllerOrWebview,
      "document.documentElement.outerHTML",
    );
    return html;
  }

  /// Evaluates JS and decodes the result, handling JSON-encoded bridges.
  static Future<String?> _js(dynamic view, String script) async {
    try {
      final result = await view.evaluateJavaScript(script);
      if (result == null) return null;
      var s = result.toString();
      if (s == 'null') return null;
      // WebKit and inappwebview bridges may return strings JSON-encoded.
      if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
        try {
          final decoded = json.decode(s);
          if (decoded is String) return decoded;
        } catch (_) {}
        return s.substring(1, s.length - 1);
      }
      return s;
    } catch (_) {
      return null;
    }
  }
}

class _ChallengeBrowser extends InAppBrowser {
  _ChallengeBrowser({required this.completer, required this.logger});

  final Completer<String?> completer;
  final AppLogger logger;
  Timer? _pollTimer;
  bool _checking = false;

  @override
  Future<void> onLoadStop(WebUri? url) async {
    if (completer.isCompleted) return;

    _pollTimer?.cancel();

    Future<void> checkPage() async {
      if (completer.isCompleted || _checking) return;
      _checking = true;

      try {
        final controller = webViewController;
        if (controller == null) return;

        final title = await controller.getTitle() ?? '';
        final body = await controller.evaluateJavascript(
          source: "document.body ? document.body.innerHTML.slice(0, 5000) : ''",
        );
        final bodyText = body?.toString() ?? '';

        if (WebviewChallengeSolver.isChallengePage(
          title: title,
          bodySnippet: bodyText,
        )) {
          logger.debug(
            'Browser verification still active',
            tag: 'ChallengeSolver',
            metadata: {'title': title},
          );
          return;
        }

        final readyState = await controller.evaluateJavascript(
          source: "document.readyState",
        );

        if (readyState?.toString() != 'complete') return;

        final html = await controller.evaluateJavascript(
          source: "document.documentElement.outerHTML",
        );
        final htmlText = html?.toString() ?? '';

        if (htmlText.length > 1000 &&
            !WebviewChallengeSolver.isChallengePage(
              title: title,
              bodySnippet: htmlText,
            )) {
          logger.info(
            'Challenge page cleared; captured browser HTML',
            tag: 'ChallengeSolver',
            metadata: {'url': url?.toString(), 'htmlLength': htmlText.length},
          );

          completer.complete(htmlText);
          _pollTimer?.cancel();
        }
      } catch (e) {
        logger.debug(
          'Browser page check failed',
          tag: 'ChallengeSolver',
          metadata: {'error': e.toString()},
        );
      } finally {
        _checking = false;
      }
    }

    await checkPage();

    if (!completer.isCompleted) {
      _pollTimer = Timer.periodic(
        const Duration(milliseconds: 1500),
        (_) => checkPage(),
      );
    }
  }

  @override
  void onExit() {
    _pollTimer?.cancel();

    if (!completer.isCompleted) {
      completer.complete(null);
    }
  }
}
