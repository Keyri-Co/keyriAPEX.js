```
 _        _______           _______ _________     _______  _______ _________ _______          
| \    /\(  ____ \|\     /|(  ____ )\__   __/    (  ___  )(  ____ )\__   __/(  ____ \|\     /|
|  \  / /| (    \/( \   / )| (    )|   ) (       | (   ) || (    )|   ) (   | (    \/( \   / )
|  (_/ / | (__     \ (_) / | (____)|   | | _____ | (___) || (____)|   | |   | (__     \ (_) / 
|   _ (  |  __)     \   /  |     __)   | |(_____)|  ___  ||  _____)   | |   |  __)     ) _ (  
|  ( \ \ | (         ) (   | (\ (      | |       | (   ) || (         | |   | (       / ( ) \ 
|  /  \ \| (____/\   | |   | ) \ \_____) (___    | )   ( || )      ___) (___| (____/\( /   \ )
|_/    \/(_______/   \_/   |/   \__/\_______/    |/     \||/       \_______/(_______/|/     \|
```


# What does the process look like?

You install the [keyriAPEX.js](https://github.com/Keyri-Co/keyriAPEX.js) script on your login page.&#x20;
You host [this iframe](https://raw.githubusercontent.com/Keyri-Co/library-keyri-connect/main/KeyriQR.html) from the same origin as your login page.&#x20;
The library does the following:

1.  It puts an iframe on the page for displaying a QR code.

2.  It listens to the iframe for decrypted API data {`APIKey`, `APISecret`, `UserId`}

3.  It uses this data to authenticate the user with the APEX-API to get a `SessionToken`

4.  It deprovisions the `APIKey` from step 2 in APEX's system via their API

5.  It stores the `SessionToken` in localStorage

6.  It directs the user to the logged-in state

# How do I use it?

Simply include this script on your login page. After the page is loaded, instantiate the class `webApex` with these arguments:

1.  The Apex-API-web-socket URL

2.  The KeyriQR URL (your iframe)

3.  The Element you want the QR-Code to render inside

```javascript
// 1.) Get an element off of the DOM you want to load our iFrame into
let targetElement = document.querySelector(".login-form__container-right");


// 2.) These are the URLs that the class will need
let ApexSocketURL = "wss://apexapi.{yourDomain}/WSGateway";
let KeyriURL = "./KeyriQR.html";


// 3.) Instantiate the class
let webApex = new WebAPEX(ApexSocketURL, KeyriURL, targetElement);

// 4.) Try connecting
await webApex.connect();

// 5.) Listen for errors IF you want to handle them
webApex.on("error",(err) => {
  console.log("ERROR DATA:",err);
})
```
