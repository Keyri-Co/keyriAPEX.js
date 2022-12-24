const path = require("path");

var keyriApex = {
  devtool: "source-map",
  entry: "./js/WebApex.js",
  mode: "production",
  output: {
    filename: "WebApex.min.js",
    path: path.resolve(__dirname, "dist"),
    pathinfo: true,
    sourceMapFilename: "WebApex.min.js.map",
    library: "WebApex",
    libraryTarget: "window",
    libraryExport: "default",
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: [".tsx", ".ts", ".js"],
  },
};


module.exports = [keyriApex];
