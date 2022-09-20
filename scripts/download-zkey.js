const axios = require("axios");
const fs = require("fs");
const { promisify } = require("util");
const stream = require("stream");

const downloadZKey = async () => {
  const finishedDownload = promisify(stream.finished);

  const writer = fs.createWriteStream("circuit.zkey");

  const response = await axios({
    method: "get",
    url: "https://storage.googleapis.com/proving_keys/circuit.zkey",
    responseType: "stream"
  });

  response.data.pipe(writer);
  await finishedDownload(writer);
};

module.exports = {
  downloadZKey
};
