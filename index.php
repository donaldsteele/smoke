<?php
/********** CONFIGURATION START **********/

/****************/
/* commands available for execution */
/* you can list anything here you wish to execute including scripts */
$commands = [];
add_command($commands, 'ping test', 'ping -c 6 127.0.0.1');
add_command($commands, 'list the directory', 'ls -alh');
add_command($commands, 'available disk space', 'df -h');


/****************/
/* user Auth */

$realm = 'Restricted area';
$cancel_text = "Authentication is required to access this system";
/* username and passwords of the authorized users */
$users = [
    'admin' => 'admin',
    'user1' => 'randomP@ssword!'
];
/* set to true if you wish to disable authentication , useful for when you want to handle authentication upstream */
$disable_auth = false;

/****************/
/* display */

//$theme_style='light';
$theme_style='dark';

/****************/
/* encryption */

/* this key is used to encrypt the audit_log entries */
/* this was generated from https://www.random.org/cgi-bin/randbyte?nbytes=32&format=h */
/* broken up on 2 lines to make it easier to cut and paste */
/* DO NOT LEAVE THIS AS DEFAULT else an attacker can download your log from yoursite.com/log.txt and decrypt it */

$log_key  = '7c 86 df c7 f4 38 60 59 e5 bd f5 2a e0 d6 7c f8';
$log_key .= '3b c0 e7 0c 86 a0 47 2c 0e 0c ab 74 c0 f3 01 18';


/********** CONFIGURATION END **********/



 if ($disable_auth == true) {
    $current_user = 'admin';
} else {
    $current_user = check_auth($users, $realm, $cancel_text);
}

 if ($current_user == '') {
     die('Authentication error');
 }


 $log_key = hex2bin(str_replace(" ",'',$log_key));


/***********************************************************/
/*                                                         */
/*               SECTION: Routing / Main Code Entry        */
/*                                                         */
/***********************************************************/



/* routing section */

if (array_key_exists('command', $_GET) && is_numeric($_GET['command'])) {
    emit_command($commands[$_GET['command']]['command'], $current_user, $log_key);
} elseif (array_key_exists('action', $_GET)) {
    switch ($_GET['action']) {
        case 'logout':
            log_out($commands,$current_user,$disable_auth,$theme_style );
            break;
        case 'audit_log':
            emit_audit_log($log_key);
            break;
        default:
    }
} else {
    display_index_page($commands,$current_user,$disable_auth,$theme_style);
}


/***********************************************************/
/*                                                         */
/*               SECTION: Command Execution                */
/*                                                         */
/***********************************************************/

function add_command(&$commands, $description, $command)
{

    $commands[] = [
        'command' => $command,
        'description' => $description
    ];

}

function emit_audit_log($log_key) {
    disable_buffering();
    file_get_contents('log.txt');

    $handle = fopen('log.txt', "r");
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            try {
                echo safeDecrypt($line, $log_key) . "\n";
            } catch (Exception $e) {
                echo "log decryption error!";
            }
        }
        fclose($handle);
    } else {
        echo "error opening file";
    }

}


/* Execute a command and record output to log */
function emit_command($cmd, $current_user, $log_key)
{
    disable_buffering();
    $tmpfname = tempnam("/tmp", "smoke-");

    system($cmd . ' | tee ' . $tmpfname);
    $results = file_get_contents($tmpfname);

    $log = [
        'date' => date('c'),
        'user' => $current_user,
        'command' => $cmd,
        'result' => $results,
    ];
    file_put_contents('log.txt', safeEncrypt(json_encode($log),$log_key) . "\n", FILE_APPEND);
    unlink($tmpfname);
}

function disable_buffering() {
    header('X-Content-Type-Options: nosniff');
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');

    // Turn off output buffering
    ini_set('output_buffering', 'off');
    // Turn off PHP output compression
    ini_set('zlib.output_compression', false);
    // Implicitly flush the buffer(s)
    ini_set('implicit_flush', true);
    ob_implicit_flush(true);
    // Clear, and turn off output buffering
    while (ob_get_level() > 0) {
        // Get the curent level
        $level = ob_get_level();
        // End the buffering
        ob_end_clean();
        // If the current level has not changed, abort
        if (ob_get_level() == $level) break;
    }
    // Disable apache output buffering/compression
    if (function_exists('apache_setenv')) {
        apache_setenv('no-gzip', '1');
        apache_setenv('dont-vary', '1');
    }

}


function safeEncrypt(string $message, string $key): string
{
    if (mb_strlen($key, '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        throw new RangeException('Key is not the correct size (must be 32 bytes).');
    }
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    $cipher = base64_encode(
        $nonce.
        sodium_crypto_secretbox(
            $message,
            $nonce,
            $key
        )
    );
    sodium_memzero($message);
    sodium_memzero($key);
    return $cipher;
}

function safeDecrypt(string $encrypted, string $key): string
{
    $decoded = base64_decode($encrypted);
    $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
    $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

    $plain = sodium_crypto_secretbox_open(
        $ciphertext,
        $nonce,
        $key
    );
    if (!is_string($plain)) {
        throw new Exception('Invalid MAC');
    }
    sodium_memzero($ciphertext);
    sodium_memzero($key);
    return $plain;
}


/***********************************************************/
/*                                                         */
/*               SECTION: Authentication                   */
/*                                                         */
/***********************************************************/

function check_auth($users, $realm, $cancel_text)
{
    if (empty($_SERVER['PHP_AUTH_DIGEST'])) {
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Digest realm="' . $realm .
            '",qop="auth",nonce="' . uniqid() . '",opaque="' . md5($realm) . '"');

        die($cancel_text);
    }


// analyze the PHP_AUTH_DIGEST variable
    if (!($data = http_digest_parse($_SERVER['PHP_AUTH_DIGEST'])) ||
        !isset($users[$data['username']]))
        die('Wrong Credentials!');


// generate the valid response
    $A1 = md5($data['username'] . ':' . $realm . ':' . $users[$data['username']]);
    $A2 = md5($_SERVER['REQUEST_METHOD'] . ':' . $data['uri']);
    $valid_response = md5($A1 . ':' . $data['nonce'] . ':' . $data['nc'] . ':' . $data['cnonce'] . ':' . $data['qop'] . ':' . $A2);

    if ($data['response'] != $valid_response)
        die('Wrong Credentials!');

// ok, valid username & password
    return $data['username'];
}


// function to parse the http auth header
function http_digest_parse($txt)
{
    // protect against missing data
    $needed_parts = array('nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1);
    $data = array();
    $keys = implode('|', array_keys($needed_parts));

    preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

    foreach ($matches as $m) {
        $data[$m[1]] = $m[3] ? $m[3] : $m[4];
        unset($needed_parts[$m[1]]);
    }

    return $needed_parts ? false : $data;
}

/***********************************************************/
/*                                                         */
/*               SECTION: Page Display                     */
/*                                                         */
/***********************************************************/

/** @noinspection CssInvalidPropertyValue */
function print_head($commands, $current_user, $disable_auth, $theme_style) {

    /** @noinspection CssUnknownTarget */
    /** @noinspection CssUnresolvedCustomProperty */
    print <<<_EOF
   <html lang="en" data-theme="$theme_style">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@latest/css/pico.min.css">
    <title>Smoke</title>
    <style>
    
    html {
        background-color: #f2f7fd;
        background-image: url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M20 20.5V18H0v-2h20v-2H0v-2h20v-2H0V8h20V6H0V4h20V2H0V0h22v20h2V0h2v20h2V0h2v20h2V0h2v20h2V0h2v20h2v2H20v-1.5zM0 20h2v20H0V20zm4 0h2v20H4V20zm4 0h2v20H8V20zm4 0h2v20h-2V20zm4 0h2v20h-2V20zm4 4h20v2H20v-2zm0 4h20v2H20v-2zm0 4h20v2H20v-2zm0 4h20v2H20v-2z' fill='%23dde1ec' fill-opacity='0.4' fill-rule='evenodd'/%3E%3C/svg%3E");
    }   
    html[data-theme='dark'] {
        background-color: #141e27;
         background-image: url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M20 20.5V18H0v-2h20v-2H0v-2h20v-2H0V8h20V6H0V4h20V2H0V0h22v20h2V0h2v20h2V0h2v20h2V0h2v20h2V0h2v20h2v2H20v-1.5zM0 20h2v20H0V20zm4 0h2v20H4V20zm4 0h2v20H8V20zm4 0h2v20h-2V20zm4 0h2v20h-2V20zm4 4h20v2H20v-2zm0 4h20v2H20v-2zm0 4h20v2H20v-2zm0 4h20v2H20v-2z' fill='%2339546c' fill-opacity='0.4' fill-rule='evenodd'/%3E%3C/svg%3E");
    }
    body>main {
    padding-top:0px;
    margin-top: 0px;
    }
    body>main>article {
    margin-top: 0px;
    }
       .pre {
            -moz-appearance: textfield-multiline;
            -webkit-appearance: textarea;
            border: 1px solid gray;
            font: medium -moz-fixed;
            font: -webkit-small-control;
            height: calc(100vh / 3);;
            overflow: auto;
            padding: 2px;
            resize: both;
            width: 100%;
            font-family: "Courier New", monospace;
            white-space: pre;
        }
        
        .grid>* {
           padding: calc(var(--spacing)/ 2) 0;
           border-radius: var(--border-radius);
           background: var(--code-background-color);
           font-size: 87.5%;
           text-align: center;
}
        #audit_results > article > details > div.grid > div {
        display: block;
        background: var(--code-background-color);      
        }
        
        .grid_header>* {
        background: var(--primary-focus);
        }
    </style>
  </head>
_EOF;

}


function log_out($commands,$current_user,$disable_auth,$theme_style)
{
    header('HTTP/1.1 401 Unauthorized');

print_head($commands,$current_user,$disable_auth,$theme_style);
print <<<_EOF
  <body>
      <!-- Nav -->
    <nav class="container-fluid">
      <ul>
        <li><a href="./" class="contrast" onclick="event.preventDefault()"><strong>Smoke</strong></a></li>
      </ul>      
    </nav><!-- ./ Nav -->     
    <main class="container">
        <article>
            <p>Click <a href="/">Here</a> to login </p>
       </article>            
    </main>         
  </body>
</html>
_EOF;


    return true;


}





function display_index_page($commands,$current_user,$disable_auth,$theme_style)
{

    $self = basename(__FILE__) ;
    $cbo_options = "";

    foreach ($commands as $key => $entry) {
        $cbo_options .= sprintf("<option value=\"%s\")>%s</option>", $key, $entry['description']);
    }

print_head($commands,$current_user,$disable_auth,$theme_style);
    print <<<_EOF
  <body>
      <!-- Nav -->
    <nav class="container-fluid">
      <ul>
        <li><a href="./" class="contrast" onclick="event.preventDefault()"><strong>Smoke</strong></a></li>
      </ul>
      <ul>
_EOF;
    if ($disable_auth === false) {
        echo '<li><a href="?action=logout">Log Out</a></li>';
    }
    print <<<_EOF
      </ul>
    </nav><!-- ./ Nav -->     
    <main class="container">
        <article>
            <details open>
                <summary>Execute Command</summary>  
                <form>
                    <label for="command">Choose a command:</label>
                    <select name="command" id="command">
                        $cbo_options
                    </select>
                    <button id="exec" name="exec">Execute</button>
                </form>
                <div id="status"></div>
                <div id="state"></div>
                <div id="result" class="pre"></div>
            </details>

            <details>
                <summary>Audit Log</summary>
                 <form>                   
                    <button id="reload_audit_log" name="reload_audit_log">Refresh Audit Log</button>
                    <div id="audit_results" name="audit_results"></div>
                </form>            
            </details>
       </article>            
    </main>
   
        <script>
        
         update_audit_log('$self' + '?action=audit_log');
        
        document.getElementById('exec').onclick = function(event) {
             event.preventDefault();
             exec_long_poll('$self' + '?command=' + document.querySelector('#command').value);
             update_audit_log('$self' + '?action=audit_log')
        };
        
        document.getElementById('reload_audit_log').onclick = function(event) {
             event.preventDefault();
            
        };
        
        function update_audit_log(url) {
             var xhttp = new XMLHttpRequest();
                xhttp.onreadystatechange = function() {
                    if (this.readyState == 4 && this.status == 200) {
                        
                        let lines = this.responseText.split("\\n");                      
                        let new_html = '';
                        new_html = '<article>'
                        new_html +=  '<div class="grid grid_header">' +
                         '                      <div>Command</div>' +                                                                                                                                         
                                                '<div>User</div>' +
                                                '<div>Date</div>' +
                                            '</div>' +
                                            '</div>' +
                                            '<hr>'
                                             
            
                        for (var i = lines.length - 1; i >= 0; i--) {                    
                            if (lines[i].length > 0) {
                            newObj = JSON.parse(lines[i])
                            new_html += '<details>' +
                                            '<summary>' +
                                            '<div class="grid">' +                                                
                                                '<div>' + newObj.command + '</div>' +                                                                                                                                         
                                                '<div>' + newObj.user + '</div>' +
                                                '<div>' + newObj.date + '</div>' +
                                            '</div>' +
                                            '</summary>' +
                                             '<div class="pre" id="audit_log_'+i+'">' + newObj.result + '</div>' +
                                         '</details>' 
                            console.log(newObj)
                            }
                        }    
                        
                        new_html += '</article>'
                        document.getElementById("audit_results").innerHTML = new_html;
                    }
                };
            xhttp.open("GET", url, true);
            xhttp.send();
        }
                    
        
        function exec_long_poll(url) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', url, true);
            xhr.send(null);
            var timer;
             document.getElementById("status").innerHTML = "Executing"
            timer = window.setInterval(function() {
                if (xhr.readyState == XMLHttpRequest.DONE) {
                    window.clearTimeout(timer);
                   document.getElementById("status").innerHTML = "Complete"
                }
                document.getElementById("state").innerHTML = 'state: ' + xhr.readyState + '<br />';
                console.log(xhr.responseText);
                document.getElementById("result").innerHTML = xhr.responseText + '<br />';
            }, 100);
        };
        
        </script>
  </body>
</html>
_EOF;
}