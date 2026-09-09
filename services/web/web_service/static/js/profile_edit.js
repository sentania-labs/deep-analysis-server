/* Edit profile (profile_edit.html): "Detect from matches" fills the MTGO
 * usernames field from /profile/username-suggestions. */
(function () {
    'use strict';

    var btn = document.getElementById('detect-usernames-btn');
    var input = document.getElementById('mtgo-usernames');
    var statusEl = document.getElementById('detect-status');
    if (!btn || !input || !statusEl) return;

    btn.addEventListener('click', function () {
        btn.disabled = true;
        statusEl.textContent = 'Detecting...';
        fetch('/profile/username-suggestions')
            .then(function (resp) {
                if (!resp.ok) throw new Error('Request failed');
                return resp.json();
            })
            .then(function (data) {
                if (data.length === 0) {
                    statusEl.textContent = 'No usernames found in match data.';
                } else {
                    var names = data.map(function (s) { return s.username; });
                    input.value = names.join(', ');
                    statusEl.textContent = 'Found ' + data.length + ' username(s).';
                }
            })
            .catch(function () {
                statusEl.textContent = 'Could not detect usernames.';
            })
            .finally(function () {
                btn.disabled = false;
            });
    });
})();
