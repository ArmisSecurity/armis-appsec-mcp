// Primary file: renders user content without escaping
import { renderTemplate } from './template';

export function handlePage(req: any, res: any) {
    const userComment = req.query.comment;
    const html = renderTemplate(userComment);
    res.send(html);
}
