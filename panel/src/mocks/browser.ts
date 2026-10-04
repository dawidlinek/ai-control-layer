/** MSW service worker for the browser (mock mode: NEXT_PUBLIC_API_MOCKING=enabled). */
import { setupWorker } from "msw/browser";
import { handlers } from "./handlers";

export const worker = setupWorker(...handlers);
