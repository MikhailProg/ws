'use strict';

(function() {
    var ws = new WebSocket('ws://localhost:1234/cat');
    var submit = document.getElementById('submit');
    var output = document.getElementById('output');

    ws.onopen = function() {
        console.log('ws onopen');
        output.innerText = '';
        ws.onmessage = function(ev) {
            //for (var i = 0; i < ev.data.length; i++)
            //    console.log(ev.data.charCodeAt(i) + ' ' + ev.data[i]);
            output.innerText += ev.data;
        };

        ws.onclose = function(ev) {
            var msg = '\n\n[Service is unavailable: ' + ev.code + 
                                  (ev.reason ? ', ' + ev.reason + ']' : ']'); 
            console.log('ws onopen');
            output.innerText += msg;
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
