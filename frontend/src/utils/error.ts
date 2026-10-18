/**
 * Centralized safe API error message extractor.
 * Converts string errors, Axios errors, FastAPI validation lists ({ detail: [...] }),
 * FastAPI detail objects, nested errors, and unknown objects into human-readable strings.
 * Never returns `[object Object]`.
 */
export function getApiErrorMessage(error: any, fallbackMessage = "An unexpected error occurred."): string {
  if (!error) return fallbackMessage;

  if (typeof error === "string") return error;

  if (error.response?.data) {
    const data = error.response.data;

    if (typeof data === "string") return data;

    if (data.detail !== undefined && data.detail !== null) {
      if (typeof data.detail === "string") return data.detail;

      if (Array.isArray(data.detail)) {
        return data.detail
          .map((item: any) => {
            if (typeof item === "string") return item;
            if (item && typeof item === "object") {
              const field = Array.isArray(item.loc) && item.loc.length > 1 ? `${item.loc[item.loc.length - 1]}: ` : "";
              return `${field}${item.msg || JSON.stringify(item)}`;
            }
            return String(item);
          })
          .join("; ");
      }

      if (typeof data.detail === "object") {
        if (data.detail.message && typeof data.detail.message === "string") {
          return data.detail.message;
        }
        try {
          return JSON.stringify(data.detail);
        } catch {
          return fallbackMessage;
        }
      }
    }

    if (data.message && typeof data.message === "string") return data.message;
    if (data.error && typeof data.error.message === "string") return data.error.message;
  }

  if (error.message && typeof error.message === "string") {
    return error.message;
  }

  try {
    const stringified = JSON.stringify(error);
    return stringified !== "{}" ? stringified : fallbackMessage;
  } catch {
    return fallbackMessage;
  }
}
