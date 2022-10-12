class Example {
  static async onLoad() {
    console.log("onLoad called")
    const statusUrl = "/auth/status";
    const options = {
      encoding: 'direct',
    }
    const response = await Example.xhrJson(statusUrl, options);
    console.log("status result", response)
    const loggedIn = response.LoggedIn
    document.querySelector("#loggedin").style.display = loggedIn?"block":"none";
    document.querySelector("#loggedout").style.display = loggedIn?"none":"block";
    document.querySelector("#permissions").innerHTML = response.Permissions;
  }

  static async onClickLogin() {
    const username = document.querySelector("#username").value
    const password = document.querySelector("#password").value
    if (username=="" || password=="") {
      alert("Please enter a username and a password")
      return
    }
    const seconds = Math.floor(Date.now()/1000);
    const cryptword = Example.sha256sum(username + "-" + password);
    const shaInput = cryptword + "-" + seconds.toString();
    const nonce = Example.sha256sum(shaInput);
    try {
      const loginUrl = "/auth/login/";
      const formData = new FormData();
      formData.append("userid", username);
      formData.append("nonce", nonce);
      formData.append("time", seconds.toString());
      const options = {
        method: "POST",
        params: formData,
        encoding: 'direct',
      };
      const response = await Example.xhrJson(loginUrl, options);
      document.querySelector("#permissions").innerHTML = response.Permissions;
      console.log("Login succeeded")
    } catch (e) {
      alert("login failed: " + e.response)
      return
    }
    document.querySelector("#loggedin").style.display = "block"
    document.querySelector("#loggedout").style.display = "none"
    document.querySelector("#username").value = '' // Clear out username and password fields.
    document.querySelector("#password").value = ''
  }

  static async onClickLogout() {
    const result = await Example.xhrJson("/auth/logout")
    console.log("Result of logout is ", result)
    document.querySelector("#loggedin").style.display = "none"
    document.querySelector("#loggedout").style.display = "block"
  }

  static async onClickOpen() {
    const result = await Example.xhrJson("/open/hello")
    alert("Result of /open/hello: " + result)
  }

  static async onClickApi() {
    try {
      const result = await Example.xhrJson("/api/secret")
      alert("Result of /api/secret: " + result)
    } catch (e) {
      alert("Error trying /api/secret: " + e.response)
    }
  }

  static async onClickEdit() {
    try {
      const result = await Example.xhrJson("/api/edit")
      alert("Result of /api/edit: " + result)
    } catch (e) {
      alert("Error trying /api/edit: " + e.response)
    }
  }

  static async onClickEdit2() {
    try {
      const result = await Example.xhrJson("/api/edit2")
      alert("Result of /api/edit2: " + result)
    } catch (e) {
      alert("Error trying /api/edit2: " + e.response)
    }
  }

  static sha256sum(s/*string*/) {
    const s8a = new TextEncoder().encode(s);
    const r8a = sha256hash(s8a);
    const rs = Example.toHexString(r8a);
    return rs;
  }
  static toHexString(bytes/*Uint8Array*/) {
    return Array.prototype.map.call(bytes, (b) => {
      return ('0'+(b & 0xFF).toString(16)).slice(-2)
    }).join('');
  }

  static async xhrJson(url, options) {
    const response = await Example.xhrText(url, options);
    return JSON.parse(response || 'null');
  }

  static async xhrText(url, options) {
    const request = await Example.xhr(url, options);
    return request.responseText;
  }

  /* options is a map with these fields:
   *  method: "GET" or "POST"
   *  encoding: "json" or "direct"
   *  params: a map of the parameters to pass to a POST
   */
  static xhr(url, options) {
    const request = new XMLHttpRequest();
    return new Promise((resolve, reject) => {
      request.onreadystatechange = () => {
        if (request.readyState === 4) {
          if (request.status === 200) {
            try {
              resolve(request);
            } catch (e) {
              reject(e);
            }
          } else if (request.status == 401 && request.responseText == "Invalid token\n") {
            reject(request);
          } else {
            reject(request);
          }
        }
      };
      const method = (options && options.method) || "GET";
      request.open(method, url);
      const encoding = (options && options.encoding) || 'json';
      const params = (options && options.params) || {};
      if (params && encoding=='json') {
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(params));
      } else {
        request.send(params)
      }
    })
  }
}
