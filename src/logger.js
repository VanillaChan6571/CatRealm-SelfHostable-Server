const fs = require('fs');

const pteroLog = (() => {
  try {
    const fd = fs.openSync('/proc/1/fd/1', 'w');
    return (msg) => {
      fs.writeSync(fd, msg + '\n');
      console.log(msg);
    };
  } catch {
    return (msg) => console.log(msg);
  }
})();

module.exports = pteroLog;
