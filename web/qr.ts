import jsQR from 'jsqr';
import { parseAccount, type Account } from '../src/totp';
export function readTOTPQR(pixels: Uint8ClampedArray, width: number, height: number): { uri: string; account: Account } | null {
  const code = jsQR(pixels, width, height, { inversionAttempts: 'attemptBoth' });
  if (!code) return null;
  let account: Account;
  try {
    const url = new URL(code.data);
    if (url.protocol !== 'otpauth:' || url.hostname !== 'totp') throw new Error();
    account = parseAccount({ uri: code.data });
  } catch { throw new Error('This QR code is not a supported TOTP account. Scan the authenticator setup QR code.'); }
  return { uri: code.data, account };
}
export class QRScanner {
  private stream: MediaStream | null = null;
  private revision = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private started = 0;
  private canvas = document.createElement('canvas');
  constructor(private video: HTMLVideoElement, private panel: HTMLElement, private status: (text: string, error?: boolean) => void, private found: (uri: string, account: Account) => void) {}
  stop() {
    this.revision++;
    if (this.timer) clearTimeout(this.timer);
    this.stream?.getTracks().forEach(track => track.stop());
    this.stream = null;
    this.video.pause();
    this.video.srcObject = null;
    this.panel.hidden = true;
    this.canvas.width = this.canvas.height = 0;
  }
  private pixels(source: CanvasImageSource, width: number, height: number) {
    if (!width || !height) return null;
    const scale = Math.min(1, 2048 / Math.max(width, height));
    this.canvas.width = Math.max(1, Math.round(width * scale));
    this.canvas.height = Math.max(1, Math.round(height * scale));
    const ctx = this.canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('QR scanning is unavailable in this browser. Paste the setup key instead.');
    ctx.drawImage(source, 0, 0, this.canvas.width, this.canvas.height);
    const image = ctx.getImageData(0, 0, this.canvas.width, this.canvas.height);
    return readTOTPQR(image.data, image.width, image.height);
  }
  private accept(result: { uri: string; account: Account }) {
    this.stop();
    this.found(result.uri, result.account);
    this.status(`Found ${result.account.issuer || result.account.label}. Review the account and select Save account.`);
  }
  async camera() {
    this.stop();
    const revision = this.revision;
    this.status('Opening camera…');
    if (!navigator.mediaDevices?.getUserMedia) { this.status('Camera scanning is unavailable. Upload a QR image or paste the setup key.', true); return; }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
      if (revision !== this.revision) { stream.getTracks().forEach(track => track.stop()); return; }
      this.stream = stream;
      this.video.srcObject = stream;
      this.panel.hidden = false;
      await this.video.play();
      if (revision !== this.revision) return;
      this.started = Date.now();
      this.status('Point your camera at the authenticator setup QR code.');
      const scan = () => {
        if (revision !== this.revision) return;
        if (Date.now() - this.started > 60000) { this.stop(); this.status('Scanning stopped. Try again or upload a QR image.'); return; }
        try {
          if (this.video.readyState >= 2) {
            const result = this.pixels(this.video, this.video.videoWidth, this.video.videoHeight);
            if (result) { this.accept(result); return; }
          }
        } catch (error) {
          this.stop(); this.status((error as Error).message, true); return;
        }
        this.timer = setTimeout(scan, 200);
      };
      scan();
    } catch (error) {
      if (revision !== this.revision) return;
      this.stop();
      const name = (error as Error).name;
      this.status(name === 'NotAllowedError' ? 'Camera permission was denied. Allow camera access in your browser or upload a QR image.' : name === 'NotFoundError' ? 'No camera found. Upload a QR image instead.' : 'Could not open the camera. Upload a QR image instead.', true);
    }
  }
  async image(file: File) {
    this.stop();
    const revision = this.revision;
    if (!['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/bmp'].includes(file.type)) { this.status('Choose a PNG, JPEG, WebP, GIF, or BMP image.', true); return; }
    if (file.size > 12 * 1024 * 1024) { this.status('Choose an image smaller than 12 MB.', true); return; }
    this.status('Reading QR image…');
    let bitmap: ImageBitmap | undefined;
    try {
      bitmap = await createImageBitmap(file);
      if (revision !== this.revision) return;
      if (bitmap.width * bitmap.height > 50000000) throw new Error('Image is too large. Crop it around the QR code and try again.');
      const result = this.pixels(bitmap, bitmap.width, bitmap.height);
      if (!result) throw new Error('No QR code found. Choose a clearer image or crop it around the code.');
      this.accept(result);
    } catch (error) {
      if (revision === this.revision) this.status((error as Error).message || 'Could not read this image. Try a PNG or JPEG.', true);
    } finally { bitmap?.close(); this.canvas.width = this.canvas.height = 0; }
  }
}
