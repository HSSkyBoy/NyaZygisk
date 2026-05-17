let callbackCounter = 0;

function getUniqueCallbackName(prefix) {
  return `${prefix}_callback_${Date.now()}_${callbackCounter++}`;
}

function getBridge() {
  return (
    window.ksu ||
    window.kernelsu ||
    window.KernelSU ||
    window.WebUIX ||
    window.apatch ||
    window.mmrl ||
    null
  );
}

function normalizeResult(result) {
  if (!result) {
    return { code: 1, errno: 1, stdout: "", stderr: "Empty bridge result" };
  }

  return {
    code: firstDefined(result.code, result.errno, 0),
    errno: firstDefined(result.errno, result.code, 0),
    stdout: firstDefined(result.stdout, result.output, ""),
    stderr: firstDefined(result.stderr, result.error, ""),
  };
}

function firstDefined() {
  for (let i = 0; i < arguments.length; i += 1) {
    if (arguments[i] !== undefined && arguments[i] !== null) {
      return arguments[i];
    }
  }
  return undefined;
}

function normalizeCallbackResult(errno, stdout, stderr) {
  return normalizeResult({
    errno,
    code: errno,
    stdout,
    stderr,
  });
}

async function callExec(bridge, command, options = {}) {
  if (typeof bridge.exec !== "function") {
    throw new Error("Bridge does not provide exec()");
  }

  return new Promise((resolve, reject) => {
    const callbackName = getUniqueCallbackName("exec");
    let settled = false;
    let fallbackTimer = null;

    const cleanup = () => {
      if (fallbackTimer) {
        clearTimeout(fallbackTimer);
      }
      delete window[callbackName];
    };

    const settle = (callback) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };

    window[callbackName] = (errno, stdout, stderr) => {
      settle(() => resolve(normalizeCallbackResult(errno, stdout, stderr)));
    };

    try {
      const result = bridge.exec(command, JSON.stringify(options), callbackName);
      if (result instanceof Promise) {
        result.then((value) => {
          settle(() => resolve(normalizeResult(value)));
        }).catch((error) => {
          settle(() => reject(error));
        });
        return;
      }

      if (result !== undefined) {
        settle(() => resolve(normalizeResult(result)));
        return;
      }

      fallbackTimer = setTimeout(() => {
        if (settled) {
          return;
        }
        try {
          const fallbackResult = bridge.exec(command);
          if (fallbackResult instanceof Promise) {
            fallbackResult
              .then((value) => settle(() => resolve(normalizeResult(value))))
              .catch((error) => settle(() => reject(error)));
          } else {
            settle(() => resolve(normalizeResult(fallbackResult)));
          }
        } catch (fallbackError) {
          settle(() => reject(fallbackError));
        }
      }, 1200);
    } catch (error) {
      cleanup();

      try {
        const result = bridge.exec(command);
        if (result instanceof Promise) {
          result.then((value) => resolve(normalizeResult(value))).catch(reject);
        } else {
          resolve(normalizeResult(result));
        }
      } catch (fallbackError) {
        reject(fallbackError);
      }
    }
  });
}

async function exec(command, options = {}) {
  const bridge = getBridge();
  if (!bridge) {
    return {
      code: 127,
      errno: 127,
      stdout: "",
      stderr: "No supported WebUI bridge detected",
    };
  }

  try {
    return await callExec(bridge, command, options);
  } catch (error) {
    return {
      code: 1,
      errno: 1,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
    };
  }
}

window.NeoZygiskWebUi = {
  exec,
};
