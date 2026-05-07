// Imported module: inserts content directly into HTML without sanitization
export function renderTemplate(content: string): string {
    return `<div class="comment">${content}</div>`;
}
