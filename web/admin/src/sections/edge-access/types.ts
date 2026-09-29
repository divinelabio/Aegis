export interface EdgeAccessFacade {
  init(): Promise<void>;
  render(): void;
  switchTab(tabId: string): void;
  updateField(path: string, value: unknown): void;
  saveConfig(): Promise<void>;
  loadConfig(): Promise<void>;
  openProtectedAppForRoute(routeId: string): Promise<void>;
  openActivityForProtectedApp(appId: string): Promise<void>;
}
