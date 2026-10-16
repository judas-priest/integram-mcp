// mcp-server/auth-token.js
// PM-1003: refresh-токен живёт в Set-Cookie (iam/router.js:20-27), тело ответа
// login его вырезает. refresh-маршрут принимает токен из ТЕЛА — поэтому клиент
// хранит куку сам и шлёт её значение в теле. Ротация: после каждого refresh
// перечитываем и тело, и куку (повтор старого токена > 30 c отзывает family).
export function pickAccessToken(data) {
  return data?.accessToken || data?.data?.accessToken || data?.data?.token || null;
}

export function extractRefreshToken(body, setCookie) {
  if (body?.refreshToken) return body.refreshToken;
  const cookies = setCookie || [];
  for (const line of cookies) {
    const m = /(?:^|;\s*)refresh_token=([^;\s]+)/.exec(line);
    if (m && m[1]) return decodeURIComponent(m[1]);
  }
  return null;
}
