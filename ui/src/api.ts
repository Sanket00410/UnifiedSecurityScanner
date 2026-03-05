const TOKEN_STORAGE_KEY = "uss_ui_api_token";

function authHeaders(base: HeadersInit = {}): HeadersInit {
  const token = window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
  const next = new Headers(base);
  if (token) {
    next.set("Authorization", `Bearer ${token}`);
  }
  return next;
}

async function request<T>(path: string, options: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: authHeaders(options.headers)
  });

  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  const isJSON = contentType.includes("application/json");
  const payload = isJSON ? await response.json() : await response.text();

  if (!response.ok) {
    const message =
      typeof payload === "object" && payload && "message" in payload
        ? String((payload as any).message)
        : `Request failed (${response.status})`;
    const error = new Error(message) as Error & { status?: number };
    error.status = response.status;
    throw error;
  }

  return payload as T;
}

async function requestBlob(path: string, options: RequestInit): Promise<{ blob: Blob; contentType: string }> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: authHeaders(options.headers)
  });

  if (!response.ok) {
    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    const payload = contentType.includes("application/json") ? await response.json() : await response.text();
    const message =
      typeof payload === "object" && payload && "message" in payload
        ? String((payload as any).message)
        : `Request failed (${response.status})`;
    const error = new Error(message) as Error & { status?: number };
    error.status = response.status;
    throw error;
  }

  return {
    blob: await response.blob(),
    contentType: response.headers.get("content-type") || ""
  };
}

export function getJSON<T>(path: string) {
  return request<T>(path, { method: "GET" });
}

export function postJSON<T>(path: string, body: unknown) {
  return request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
}

export function putJSON<T>(path: string, body: unknown) {
  return request<T>(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
}

export function getBlob(path: string) {
  return requestBlob(path, { method: "GET" });
}

export function readToken() {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

export function saveToken(token: string) {
  window.localStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}
