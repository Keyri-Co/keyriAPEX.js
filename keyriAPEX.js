// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
//
// Class with methods to make working with subtle crypto
// easier and more obvious
//
class EZCrypto {
  constructor() {
    // super();
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     base64ToArray
  // What is this: Take a base64 string. Convert it to a Uint8Array...
  //
  // Arguments:    strng: - base64 encoded string
  //
  // Returns:      Uint8Array
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  base64ToArray(strng) {
    return Uint8Array.from(atob(strng), (c) => c.charCodeAt(0));
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     arrayToBase64
  // What is this: take a Uint8Array, make it a valid base64 string
  //
  // Arguments:    ary: - Uint8Array
  //
  // Returns:      Base64 String
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  arrayToBase64(ary) {
    return btoa(String.fromCharCode(...ary));
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     hmac (static) (async)
  // What is this: Create a cryptographic signature for a piece of data given a *SHARED* secret.
  //               Similar to ECDSA - Except both parties have to have the secret-key in advance
  //               to make it work.
  //
  // Arguments:    secret - this is the shared secret
  //               data   - this is the string you're encrypting
  //
  // Returns:      hex encoded 32 character string or something...(todo: check length - better def)
  // Notes:        https://stackoverflow.com/questions/47329132/how-to-get-hmac-with-crypto-web-api#47332317
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  static async hmac(secret, data) {
    // To do work, we need to convert text to Uint8Arrays
    let encoder = new TextEncoder("utf-8");
    let encodedSecret = encoder.encode(secret);
    let encodedData = encoder.encode(data);

    // Create our HMAC Key
    let key = await window.crypto.subtle.importKey(
      "raw",
      encodedSecret,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign", "verify"]
    );

    // HMAC Sign our data with our HMAC Key
    let sig = await window.crypto.subtle.sign("HMAC", key, encodedData);

    // Turn the signature into an array; then into hex-text
    // (todo: Maybe this is its own method...?)
    //
    let b = new Uint8Array(sig);
    let str = Array.prototype.map
      .call(b, (x) => ("00" + x.toString(16)).slice(-2))
      .join("");

    return str;
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESMakeKey (async)
  // What is this: Generate an AES Key and return its hex
  //
  // Arguments:    *NONE*
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  AESMakeKey = async () => {
    // 1.) Generate the Key
    let key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // 2.) Export to Array Buffer
    let out = await window.crypto.subtle.exportKey("raw", key);

    // 3.) Return it as b64
    return this.arrayToBase64(new Uint8Array(out));
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESEncrypt (async)
  // What is this: Given
  //
  // Arguments:    key:  base64 AES-key
  //               data: uInt8Array
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  async AESEncrypt(base_64_key, data_array) {
    // 1.) Convert out from base64 to array
    let aes_ary = this.base64ToArray(base_64_key);

    // 2.) Convert the Key-Array to a live Key
    let aes_key = await window.crypto.subtle.importKey(
      "raw",
      aes_ary.buffer,
      "AES-GCM",
      true,
      ["encrypt"]
    );

    // 3.) Create a nonce why not?
    let nonce = window.crypto.getRandomValues(new Uint8Array(16));

    // 4.) encrypt our data
    let encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data_array
    );

    // 5.) Base64 and return our data...
    return {
      ciphertext: this.arrayToBase64(new Uint8Array(encrypted)),
      nonce: this.arrayToBase64(nonce),
    };
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESDecrypt (async)
  // What is this: Given
  //
  // Arguments:    key:  base64 AES-key
  //               nonce: base64 of the nonce used at encryption (ok if it is public)
  //               ciphertext: base64 of what's been encoded
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  async AESDecrypt(base_64_key, base_64_nonce, base_64_cipher) {
    // 1.) Convert out from base64 to array
    let aes_ary = this.base64ToArray(base_64_key);
    let nonce_ary = this.base64ToArray(base_64_nonce);
    let cipher_ary = this.base64ToArray(base_64_cipher);

    // 2.) Convert the Key-Array to a live Key
    let aes_key = await window.crypto.subtle.importKey(
      "raw",
      aes_ary.buffer,
      "AES-GCM",
      true,
      ["decrypt"]
    );

    // 3.) Decrypt
    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce_ary },
      aes_key,
      cipher_ary
    );
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     ECDHMakeKeys (async)
  // What is this: Given
  //
  // Arguments:    none
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  ECDHMakeKeys = async () => {
    // Step 1) Create ECDH KeyS
    let keys = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    // Step 2) Export keys to SPKI|PKCS8 format
    let b64Keys = await Promise.all([
      window.crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
        return this.arrayToBase64(new Uint8Array(key));
      }),
      window.crypto.subtle.exportKey("pkcs8", keys.privateKey).then((key) => {
        return this.arrayToBase64(new Uint8Array(key));
      }),
    ]);

    // Step 3) Convert the keys to base64 and return...
    return { publicKey: b64Keys[0], privateKey: b64Keys[1] };
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     ECDHEncrypt (async)
  // What is this: Encrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  ECDHEncrypt = async (b64Private, b64Public, data) => {
    // 1.) convert the given keys to real keys
    let publicKey = await window.crypto.subtle.importKey(
      "spki",
      this.base64ToArray(b64Public),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
    let privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      this.base64ToArray(b64Private),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    // 2.) generate shared key
    let aes_key = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // 3.) Create a nonce why not?
    let nonce = window.crypto.getRandomValues(new Uint8Array(16));

    // 4.) encrypt our data
    let encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data
    );

    // 5.) Base64 and return our data...
    return {
      ciphertext: this.arrayToBase64(new Uint8Array(encrypted)),
      nonce: this.arrayToBase64(nonce),
    };
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     ECDHDecrypt (async)
  // What is this: Decrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //               base64nonce: string;
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  ECDHDecrypt = async (b64Private, b64Public, b64Nonce, b64data) => {
    // 1.) convert the given keys to real keys
    let publicKey = await window.crypto.subtle.importKey(
      "spki",
      this.base64ToArray(b64Public),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
    let privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      this.base64ToArray(b64Private),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );
    let nonce = this.base64ToArray(b64Nonce);
    let data = this.base64ToArray(b64data);

    // 2.) generate shared key
    let aes_key = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // 4.) encrypt our data
    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data
    );
  };
}
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
//
// Class with methods to interract with APEX
//
class WebAPEX {
  //
  // Private Class Variables
  //
  #socket; // Our WebSocket
  #radio; // Quick-and-Dirty PUB/SUB
  #socketURL; // This is the URL our websocket hits
  #iterator = 1; // Functional placeholder: This is the number of times
  // we've sent data through the websocket

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     constructor
  // What is this: class initiation methods and creation of QR iFrame
  //
  // Arguments:    socketURL: (string) - URL of the APEX WebSocket
  //               keyriURL: (string) - URL of Keyri API
  //               targetElement: (DOMElement) - this is what we are putting iframe in
  //
  // Returns:      an instance of WebAPEX
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  constructor(socketURL, targetElement) {
    // This allows us to issue custom events
    // that a class user can listen to
    //
    this.#radio = document.createDocumentFragment();
    this.#socketURL = socketURL;




    const iframeSrc = `
    <!DOCTYPE html>
    <html lang="en-US">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link href="https://static.keyri.com/library-keyri-connect/iframe.css" rel="stylesheet">
      </head>
      <body>
        <img class="pre-blurry" id="qr-target" style="height: 100%; width: 100%; z-index: -1" />
        <div
          id="qr-lay-over"
          onclick="main();"
          style="height: 100%; width: 100%; position: absolute; top: 0; left: 0; z-index: 1"
        ></div>
      </body>
    </html>
    
    <script src="https://static.keyri.com/library-keyri-connect/keyri-0.10.2.min.js"></script>
    <script>

        const postMessage = window.parent.postMessage;
        postMessage("HI MOM","*");

        self = {location: {host: top.location.host}};
        parent = {location: {origin: location.origin}};
        
        window.parent.postMessage = (a,b) => {
          console.log("POST-MESSAGE",{a,b});
          return postMessage(a,"*")
        }

        postMessage("WAIT UNTIL THEY GET A LOAD OF ME...","*");

    
    </script>
    `;

    window.addEventListener("message", this.handlePost, false);
    // Creating iframe and configure it
    const keyriQR = document.createElement("iframe");
    keyriQR.srcdoc = iframeSrc;
    keyriQR.style.padding = "50px";
    keyriQR.style.width = "350px";
    keyriQR.style.height = "350px";
    keyriQR.style.borderWidth = "0";
    keyriQR.style["vertical-align"] = "middle";
    keyriQR.style.borderWidth = "0";
    keyriQR.scrolling = "no";

    // Load the iframe onto our target
    targetElement.innerHTML = "";
    targetElement.appendChild(keyriQR);
  }

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     connect (async)
  //
  // SCOPE:        Public
  //
  // PURPOSE:      Method for creating a private websocket connection with APEX, and setting up event
  //               handlers
  //
  // ARGS:         socketURL: (string) - URL Where the websocket is connecting
  //
  // RETURNS:      event data from the socket's "onopen" method - so you know you're connected
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  connect = async () => {

    console.log("RUNNING CONNECT");
    // Try creating a websocket, and connecting
    // it to the socketURL. Return the error if
    // it bombs out...
    //
    //try{
    this.#socket = new WebSocket(this.#socketURL);

    //
    // This promise makes the method async...
    // We're connecting above...
    // We resolve the following promise once the
    // socket's `onopen` is triggered
    //
    return new Promise((resolve, reject) => {
      // Once we catch an 'onopen' event; resolve the promise
      this.#socket.onopen = (event) => {
        resolve(event);
      };

      // Listen for a message, broadcast a custom event
      // to the "i" in the response MINO
      this.#socket.onmessage = (message) => {

        console.log("CONNECT METHOD",{message});

        let eMsg = JSON.parse(message.data);

        eMsg.o = JSON.parse(eMsg.o);

        let id = eMsg.i;

        this.#broadcast(id.toString(), eMsg);
      }


      // Add a one time event listener for errors from the socket
      this.#socket.addEventListener(
        "error",
        (err) => {
          this.#broadcast("error", err);
          reject(err);
        });

      // Set a timeout to blow up after 5 seconds;
      // if it goes off; reject the promise
      setTimeout(() => {
        reject(new Error("WS connect attempt timed out..."));
      }, 5_000);
    });
  };

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     send (async)
  //
  // SCOPE:        Public
  //
  // PURPOSE:      Public Method to send arbitrary data over the web-socket
  //               and wait for response...
  //
  // ARGS:         data: (string) - whatever you're sending across the wire
  //
  // RETURNS:      event data from the socket's "onmessage" method
  //
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  send = async (data) => {
    // Keep track of the iterator by adding 2 every time (our i's will be odd)
    this.#iterator += 2;

    // https://stackoverflow.com/questions/58030661/promisify-event-based-pattern
    return new Promise((resolve, reject) => {

      // Figure out what custom call we're listening for...
      let iterator = JSON.parse(data).i;

      // Add a one time event listener for custom events of type `iterator`
      this.on(iterator.toString(),(evnt) => {

          // 0.) Pull data from event
          let eData = evnt.detail;

          // 1.) See if the object "o" has an `errormsg`. If so throw an error.
          if (typeof eData.o.errormsg == "string") {
            this.#broadcast("error", eData);
            reject(eData);
            return false;
          } else {
            resolve(eData);
          }

        });


      // //////////////////////////////////////////////////////////////////////
      // Now that listeners are set up; send data to websocket api
      // //////////////////////////////////////////////////////////////////////
      this.#socket.send(data);

      // //////////////////////////////////////////////////////////////////////
      // To ensure that this doesn't hang forever, wait at most 5 seconds;
      // then reject the whole thing
      // //////////////////////////////////////////////////////////////////////
      setTimeout(() => {
        reject(new Error("WS send attempt timed out..."));
      }, 5_000);
    });
  };

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     authUser (async)
  //
  // SCOPE:        Public
  //
  // PURPOSE:      Public Method to send/receive authentication data
  //               from APEX API
  //
  // ARGS:         APIKey: (string) - given at account signup
  //               APISecret: (string) - given at account signup
  //               UserId: (string) - given at account signup
  //
  // RETURNS:      whatever the API returns (todo - give better info HERE)
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  authUser = async (APIKey, APISecret, UserId) => {
    // Create a nonce and signature per APEX API Requirements
    let Nonce = window.crypto
      .getRandomValues(new Uint8Array(32))
      .join("")
      .substring(0, 13);
    let Signature = await EZCrypto.hmac(
      APISecret,
      `${Nonce}${UserId}${APIKey}`
    );

    // Create a credentials object
    const creds = { Nonce, UserId, APIKey, Signature };

    // Stringify and send it...
    let payload = JSON.stringify({
      m: 0,
      i: this.#iterator,
      n: "AuthenticateUser",
      o: JSON.stringify(creds),
    });

    let data = await this.send(payload);

    return data;
  };

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     destroyAPIKey (async)
  //
  // SCOPE:        Public
  //
  // PURPOSE:      Public Method to DESTROY user's API Key ***AFTER***
  //               they are logged in...
  //
  // ARGS:         APIKey: (string) - given at account signup
  //               UserId: (string) - given at account signup
  //
  // RETURNS:      whatever the API returns (todo - give better info HERE)
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  destroyAPIKey = async (APIKey, UserId) => {
    let payload = JSON.stringify({
      m: 0,
      i: this.#iterator,
      n: "RemoveUserAPIKey",
      o: JSON.stringify({ UserId: UserId, APIKey: APIKey }),
    });

    let data = await this.send(payload);

    return data;
  };

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     getAPIKeys (async)
  //
  // SCOPE:        Public
  //
  // PURPOSE:      Public Method to GET ALL API Keys ***AFTER***
  //               they are logged in... (optional)
  //
  // ARGS:         UserId: (string) - given at account signup
  //
  // RETURNS:      APIKey Array Object
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  getAPIKeys = async (APIKey, UserId) => {
    let payload = JSON.stringify({
      m: 0,
      i: this.#iterator,
      n: "GetUserAPIKeys",
      o: JSON.stringify({ UserId: UserId, APIKey: APIKey }),
    });

    let data = await this.send(payload);

    return data;
  };

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     on
  //
  // SCOPE:        Public
  //
  // PURPOSE:      exposes a way for a user to listen to events that the class
  //               emits. SUPER USEFUL FOR ERROR HANDLING...!
  //
  //
  //
  // ARGS:         eventType: (string) - what is the name of the event you're
  //                          listening for?
  //
  //               eventHandler: (function) - what do you want to do
  //
  // RETURNS:      whatever the API returns (todo - give better info HERE)
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  on = (eventType, eventHandler) => {
    this.#radio.addEventListener(eventType, eventHandler);
  };

  // //////////////////////////////////////////////////////////////////////////
  //
  // FUNCTION:     broadcast
  //
  // SCOPE:        PRIVATE
  //
  // PURPOSE:      here's how we throw up events for external listeners to...
  //               listen to.
  //
  //
  //
  // ARGS:         eventType: (string) - what is the name of the event you're
  //                          listening for?
  //
  //               eventData: (object) - information you want to respond with
  //                          to the event handler
  //
  // RETURNS:      whatever the API returns (todo - give better info HERE)
  //
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  #broadcast = (eventType, eventData) => {
    this.#radio.dispatchEvent(
      new CustomEvent(eventType, { detail: eventData })
    );
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     handlePost (private) (async)
  // What is this: THIS IS WHAT COMES BACK FROM THE API THROUGH THE IFRAME!!!
  //
  // Arguments:    message: - data coming from iframe
  //
  // Returns:      nothing
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  //
  handlePost = async (message) => {

    console.log("HANDLE-POST", {message});

    // Check messages from iframe with required action
    if (message?.data?.type === "session_validate") {
   
      let mobile_data = JSON.parse(message?.data?.data);
      let mobile_data_payload = JSON.parse(mobile_data?.o);
      let mobile_data_payload_token = mobile_data_payload.SessionToken;

      localStorage.token = mobile_data_payload_token;

      setTimeout(() => {
        window.location.reload();
      }, 100);
    }
  };
}
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\


// 1.) Get an element off of the DOM you want to load our iFrame into
let targetElement = document.querySelector(".login-form__container-right");
let yourDomain = "bitazza.com";

// 2.) These are the URLs that the class will need
let ApexSocketURL = `wss://apexapi.${yourDomain}/WSGateway`;
let KeyriURL = "./KeyriQR.html";


// 3.) Instantiate the class
let webApex = new WebAPEX(ApexSocketURL, targetElement);

// 4.) Try connecting
await webApex.connect();

// 5.) Listen for errors IF you want to handle them
webApex.on("error",(err) => {
  console.log("ERROR DATA:",err);
})