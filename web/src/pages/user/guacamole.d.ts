// Minimal typings for the parts of guacamole-common-js the Desktop page uses.
declare module 'guacamole-common-js' {
  export class WebSocketTunnel {
    constructor(url: string)
    onerror: ((status: { code?: number; message?: string }) => void) | null
  }
  export class Display {
    getElement(): HTMLElement
  }
  export class Client {
    constructor(tunnel: WebSocketTunnel)
    connect(data?: string): void
    disconnect(): void
    getDisplay(): Display
    sendMouseState(state: unknown): void
    sendKeyEvent(pressed: number, keysym: number): void
    sendSize(width: number, height: number): void
    onerror: ((status: { code?: number; message?: string }) => void) | null
    onstatechange: ((state: number) => void) | null
  }
  export class Mouse {
    constructor(element: HTMLElement)
    onmousedown: ((state: unknown) => void) | null
    onmouseup: ((state: unknown) => void) | null
    onmousemove: ((state: unknown) => void) | null
  }
  export class Keyboard {
    constructor(element: Document | HTMLElement)
    onkeydown: ((keysym: number) => boolean | void) | null
    onkeyup: ((keysym: number) => void) | null
  }
  const Guacamole: {
    WebSocketTunnel: typeof WebSocketTunnel
    Client: typeof Client
    Mouse: typeof Mouse
    Keyboard: typeof Keyboard
  }
  export default Guacamole
}
