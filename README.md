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

# What Is This?

Browser script for handling Keyri Auth with the APEX crypto platform



# What does the process look like?

You install the [keyriAPEX.js](https://github.com/Keyri-Co/keyriAPEX.js) script on your page. From the perspective of this library, the process of logging in a user looks like this:

1.  It puts an iframe on the page for displaying a QR code.
2.  It listens to the iframe for decrypted API data {`APIKey`, `APISecret`, `UserId`}
3.  It uses this data to authenticate the user with the APEX-API to get a `SessionToken`
4.  It stores the `SessionToken` in localStorage
5.  It deprovisions the `APIKey` from step 2 in APEX's system via their API

# How do I use it?

Basically, include this script on your login page. After the page is loaded, instantiate the class `webApex` with these arguments:

1.  The Apex-API-web-socket URL
2.  The Keyri URL
3.  The Element you want the QR-Code to land on

```javascript

// 1.) Get an element off of the DOM you want to load our iFrame into
//
const TargetElement = document.querySelector("#element_to_put_iframe_in");


// 2.) These are the URLs that the class will need
//
const ApexSocketURL = `wss://${your_APEX_websocket_endpoint}`;
const KeyriURL = `https://api.keyri.co/widget/${your_keyri_id}/login?link=false&aesKey=true`;


// 3.) Instantiate the class
//
const webApex = new WebAPEX(ApexSocketURL, KeyriURL, targetElement);

// 4.) Start a connection
//
await webApex.connect();

// 5.) Listen for errors IF you want to handle them
//
webApex.on("error",(err) => {
  console.log("ERROR DATA:",err);
})
```