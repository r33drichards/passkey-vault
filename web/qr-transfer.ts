/** Clipboard and drop images go through the same local decoder as file selection. */
export function transferImage(data: DataTransfer | null): File | null {
  if (!data) return null;
  for (const item of Array.from(data.items || [])) {
    if (item.kind === 'file' && item.type.startsWith('image/')) {
      const file = item.getAsFile();
      if (file) return file;
    }
  }
  return Array.from(data.files || []).find(file => file.type.startsWith('image/')) || null;
}
function hasFiles(data: DataTransfer | null) {
  return !!data && (Array.from(data.types || []).includes('Files') || Array.from(data.items || []).some(item => item.kind === 'file'));
}
export function bindQRImageTransfer(target: EventTarget, dialog: HTMLDialogElement, zone: HTMLElement, image: (file: File) => void, error: (message: string) => void) {
  let depth = 0;
  const clear = () => { depth = 0; zone.classList.remove('drag-active'); };
  target.addEventListener('paste', event => {
    if (!dialog.open) return;
    const paste = event as ClipboardEvent, file = transferImage(paste.clipboardData);
    if (!file) return; // Preserve ordinary text pasting in setup-key and URI fields.
    paste.preventDefault(); clear(); image(file);
  });
  target.addEventListener('dragenter', event => {
    if (!dialog.open || !hasFiles((event as DragEvent).dataTransfer)) return;
    event.preventDefault(); depth++; zone.classList.add('drag-active');
  });
  target.addEventListener('dragover', event => {
    const drag = event as DragEvent;
    if (!dialog.open || !hasFiles(drag.dataTransfer)) return;
    drag.preventDefault();
    if (drag.dataTransfer) drag.dataTransfer.dropEffect = 'copy';
    zone.classList.add('drag-active');
  });
  target.addEventListener('dragleave', () => {
    if (--depth <= 0) clear();
  });
  target.addEventListener('drop', event => {
    const drop = event as DragEvent;
    clear();
    if (!dialog.open || !hasFiles(drop.dataTransfer)) return;
    drop.preventDefault(); // Prevent the browser from navigating to the dropped file.
    const file = transferImage(drop.dataTransfer);
    if (file) image(file); else error('Drop a QR image file, such as PNG or JPEG.');
  });
  dialog.addEventListener('close', clear);
  return clear;
}
