export class GameError extends Error {
  constructor(public code: string, public status = 400, public field?: string) {
    super(code);
  }
}
