/**
 * CleanTalk offline JavaScript check.
 *
 * Copies the server generated hash from the data-ct-js-key attribute into a cookie.
 * The backend compares the cookie with the same hash when the moderate server is unreachable:
 * a matching value proves that JavaScript is executed in the visitor browser.
 */
(function () {
    'use strict';

    var self = document.currentScript || (function () {
        var scripts = document.getElementsByTagName('script');
        return scripts[scripts.length - 1];
    })();

    if (!self) {
        return;
    }

    var key = self.getAttribute('data-ct-js-key');

    // Reject anything but a sha256 hex digest to keep arbitrary data out of the cookie header
    if (!key || !/^[a-f0-9]{64}$/.test(key)) {
        return;
    }

    var secure = location.protocol === 'https:' ? '; secure' : '';

    document.cookie = 'ct_js_check=' + key + '; path=/; max-age=86400; samesite=lax' + secure;
})();
