export type ErrorCode =
  | "bad_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "internal";

const STATUS: Record<ErrorCode, number> = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  rate_limited: 429,
  internal: 500,
};

export class HttpError extends Error {
  readonly status: number;
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.status = STATUS[code];
  }
}

export const badRequest = (msg: string, details?: unknown) => new HttpError("bad_request", msg, details);
export const unauthorized = (msg = "Unauthorized") => new HttpError("unauthorized", msg);
export const forbidden = (msg = "Forbidden") => new HttpError("forbidden", msg);
export const notFound = (msg = "Not found") => new HttpError("not_found", msg);
export const conflict = (msg: string) => new HttpError("conflict", msg);
export const rateLimited = (msg = "Too many requests") => new HttpError("rate_limited", msg);
