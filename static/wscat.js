'use strict';

(function() {
    var ws = new WebSocket('ws://localhost:1234/cat');
    var submit = document.getElementById('submit');
    var output = document.getElementById('output');

    ws.onopen = function() {
        console.log('ws onopen');
        ws.onmessage = function(ev) {
            output.innerText += ev.data;
        };

        ws.onclose = function(ev) {
            var msg = '[Service is unavailable: ' + ev.code + 
                                  (ev.reason ? ', ' + ev.reason + ']' : ']'); 
            console.log('ws onopen');
            output.innerText = msg;
        };

        submit.addEventListener('submit',
            function(ev) {
                ev.stopPropagation();
                ev.preventDefault();
                ws.send(document.getElementById('message').value + '\n');
                submit.reset();
         });
    };

    ws.onerror = function(ev) {
        output.innerText = 'WebSocket is not connected';
    };
})();
