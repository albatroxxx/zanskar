// Minimal typings for the parts of guacamole-common-js the Desktop page uses.
declare module 'guacamole-common-js' {
  export interface Status { code?: number; message?: string }

  export class WebSocketTunnel {
    constructor(url: string)
    onerror: ((status: Status) => void) | null
    oninstruction: ((opcode: string, args: string[]) => void) | null
  }
  /** Streams a stored recording over HTTP, parsing instructions as they arrive.
   *  SessionRecording's Blob source is unusable upstream (it parses an
   *  uninitialised blob), so playback feeds it one of these instead. */
  export class StaticHTTPTunnel {
    constructor(url: string, crossDomain?: boolean, extraHeaders?: Record<string, string>)
    onerror: ((status: Status) => void) | null
    oninstruction: ((opcode: string, args: string[]) => void) | null
    connect(data?: string): void
    disconnect(): void
  }
  export class Display {
    getElement(): HTMLElement
    getWidth(): number
    getHeight(): number
    getScale(): number
    scale(scale: number): void
    onresize: ((width: number, height: number) => void) | null
  }
  /** Replays a stored guacd instruction stream through a Display. */
  export class SessionRecording {
    constructor(source: Blob | WebSocketTunnel | StaticHTTPTunnel)
    connect(): void
    disconnect(): void
    getDisplay(): Display
    getDuration(): number
    getPosition(): number
    isPlaying(): boolean
    play(): void
    pause(): void
    seek(position: number, callback?: () => void): void
    onload: (() => void) | null
    onerror: ((message: string) => void) | null
    onabort: (() => void) | null
    onprogress: ((duration: number, parsed: number) => void) | null
    onplay: (() => void) | null
    onpause: (() => void) | null
    onseek: ((position: number, current: number, total: number) => void) | null
  }
  export class InputStream {
    index: number
    onblob: ((data: string) => void) | null
    onend: (() => void) | null
    sendAck(message: string, code: number): void
  }
  export class OutputStream {
    index: number
    onack: ((status: Status) => void) | null
    sendBlob(data: string): void
    sendEnd(): void
  }
  export class ArrayBufferReader {
    constructor(stream: InputStream)
    ondata: ((buffer: ArrayBuffer) => void) | null
    onend: (() => void) | null
  }
  export class ArrayBufferWriter {
    constructor(stream: OutputStream)
    blobLength: number
    onack: ((status: Status) => void) | null
    sendData(data: ArrayBuffer | ArrayBufferView): void
    sendEnd(): void
  }
  export class JSONReader {
    constructor(stream: InputStream)
    onprogress: ((length: number) => void) | null
    onend: (() => void) | null
    getJSON(): unknown
  }
  export class GuacObject {
    static ROOT_STREAM: string
    static STREAM_INDEX_MIMETYPE: string
    index: number
    onundefine: (() => void) | null
    requestInputStream(name: string, bodyCallback?: (stream: InputStream, mimetype: string) => void): void
    createOutputStream(mimetype: string, name: string): OutputStream
  }
  export class Client {
    constructor(tunnel: WebSocketTunnel)
    connect(data?: string): void
    disconnect(): void
    getDisplay(): Display
    sendMouseState(state: unknown): void
    sendKeyEvent(pressed: number, keysym: number): void
    sendSize(width: number, height: number): void
    onerror: ((status: Status) => void) | null
    onstatechange: ((state: number) => void) | null
    onfilesystem: ((object: GuacObject, name: string) => void) | null
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
    StaticHTTPTunnel: typeof StaticHTTPTunnel
    Client: typeof Client
    Mouse: typeof Mouse
    Keyboard: typeof Keyboard
    ArrayBufferReader: typeof ArrayBufferReader
    ArrayBufferWriter: typeof ArrayBufferWriter
    JSONReader: typeof JSONReader
    Object: typeof GuacObject
    SessionRecording: typeof SessionRecording
  }
  export default Guacamole
}
