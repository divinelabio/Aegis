type ToastType = 'success' | 'error' | 'warning' | 'info';
type MaybeAsyncVoidFn = () => void | Promise<void>;

interface ToastApi {
  container: HTMLElement | null;
  init(): void;
  show(message: unknown, type?: ToastType, title?: string | null): void;
}

interface ModalOptions {
  panelClass?: string;
  overlayClass?: string;
  closeOnBackdrop?: boolean;
}

interface SectionUIApi {
  icons: Record<string, string>;
  modalKeyHandler?: ((event: KeyboardEvent) => void) | null;
  modalFocusReturnTarget?: HTMLElement | null;
  renderModuleHeader(
    icon: string,
    title: string,
    desc: string,
    toggleField: string | null,
    enabled: boolean,
    configName: string
  ): string;
  renderStatCard(label: string, value: number | string, color: string): string;
  renderSaveButton(configName: string): string;
  renderLoading(message?: string): string;
  renderError(message: string, retryFunc: string): string;
  showToast(message: string, type?: ToastType): void;
  getElement(target: string | Element | null | undefined): HTMLElement | null;
  setHidden(target: string | Element | null | undefined, hidden?: boolean): HTMLElement | null;
  toggleHidden(target: string | Element | null | undefined): boolean;
  setOpen(
    target: string | Element | null | undefined,
    isOpen?: boolean,
    options?: { openClass?: string; hiddenClass?: string; expandedTarget?: string | Element | null }
  ): HTMLElement | null;
  closeAll(selector: string, exceptId?: string | null, options?: { openClass?: string; hiddenClass?: string }): void;
  renderPageHeader(title: string, subtitle?: string, actions?: string): string;
  renderConfigPageHero(title: string, subtitle?: string, kicker?: string, actions?: string): string;
  renderConfigConsoleHeader(options: {
    title: string;
    category?: string;
    meta?: string;
    status?: Array<{ label: string; tone?: string }>;
    actions?: string;
  }): string;
  renderConfigSectionNav(
    tabs: Array<{ id: string; name: string; icon?: string }>,
    activeId: string,
    action: string,
    actionAttr?: string,
    valueAttr?: string
  ): string;
  renderMetricStrip(metrics: Array<{ label: string; value: string | number; tone?: string }>): string;
  renderOperatorFrame(options: {
    title: string;
    kicker?: string;
    subtitle?: string;
    status?: Array<{ label: string; tone?: string }>;
    actions?: string;
    tabs?: Array<{ id: string; name: string; icon?: string }>;
    activeTab?: string;
    tabAction?: string;
    tabActionAttr?: string;
    tabValueAttr?: string;
    content: string;
    className?: string;
  }): string;
  renderResourceWorkspace(options: {
    title: string;
    breadcrumbLabel: string;
    breadcrumbCurrent: string;
    breadcrumbAttrs: string;
    status?: string;
    metadata?: string;
    actions?: string;
    tabs?: Array<{ id: string; name: string; icon?: string }>;
    activeTab?: string;
    tabAction?: string;
    tabActionAttr?: string;
    tabValueAttr?: string;
    content: string;
    className?: string;
  }): string;
  renderLineTabs(
    tabs: Array<{ id: string; name: string; icon?: string }>,
    activeId: string,
    options: {
      action: string;
      actionAttr?: string;
      valueAttr?: string;
      ariaLabel?: string;
    }
  ): string;
  renderOperatorMetricStrip(metrics: Array<{ label: string; value: string | number; sub?: string; tone?: string }>, className?: string): string;
  renderOperatorBackButton(options: {
    label: string;
    ariaLabel?: string;
    attrs: string;
    className?: string;
  }): string;
  renderOperatorSection(title: string, content: string, options?: { subtitle?: string; actions?: string; className?: string }): string;
  renderOperatorControlRow(options: {
    title: string;
    titleHeadingLevel?: 2 | 3 | 4 | 5 | 6;
    description?: string;
    icon?: string;
    enabled?: boolean;
    actions?: string;
    content?: string;
    className?: string;
    attrs?: string;
  }): string;
  renderSaveActionBar(options: {
    actionAttr: string;
    resetAction: string;
    saveAction: string;
    resetLabel?: string;
    saveLabel?: string;
    className?: string;
    resetAttrs?: string;
    saveAttrs?: string;
  }): string;
  markSaveActionBarDirty(actionAttr: string): void;
  markSaveActionBarClean(actionAttr?: string): void;
  renderStickyActionBar(content: string, className?: string): string;
  renderConfigPanel(title: string, content: string, options?: { actions?: string; className?: string }): string;
  renderStatusPill(label: string, tone?: string): string;
  renderActionMenu(options: {
    id: string;
    label?: string;
    ariaLabel: string;
    items: Array<{
      label: string;
      attrs: string;
      tone?: 'default' | 'danger';
      disabled?: boolean;
    }>;
    className?: string;
  }): string;
  renderEnterpriseTable(options: {
    columns: string[];
    rows: string[][];
    emptyTitle?: string;
    emptyMessage?: string;
    emptyAction?: string;
    className?: string;
  }): string;
  renderTableScrollHint(): string;
  renderInfoTooltip(text: string, options?: { placement?: 'top' | 'right' | 'bottom' | 'left'; className?: string }): string;
  renderEmptyState(title: string, message: string, icon?: string, action?: string): string;
  renderSwitch(options: {
    id?: string;
    checked?: boolean;
    label?: string;
    labelId?: string;
    attrs?: string;
    className?: string;
  }): string;
  showModal(content: string, options?: ModalOptions): void;
  closeModal(): void;
  openConfirmModal(
    title: string,
    message: string,
    btnText: string,
    btnColor: string,
    callback: MaybeAsyncVoidFn | string
  ): void;
}

interface RouterApi {
  current: string;
  dashboardTab: string;
  views: Record<string, string>;
  navigate(target: string, sourceLink?: Element | null, options?: { replace?: boolean }): void;
  navigateToRuleEditor?: (filePath: string) => void;
}

interface AdminDOMApi {
  getById<T extends HTMLElement = HTMLElement>(id: string): T | null;
  resolveElement(target: string | Element | null | undefined): HTMLElement | null;
  query<T extends Element = HTMLElement>(selector: string, root?: Document | Element): T | null;
  queryAll<T extends Element = HTMLElement>(selector: string, root?: Document | Element): T[];
  getInput(id: string): HTMLInputElement | null;
  getSelect(id: string): HTMLSelectElement | null;
  getTextarea(id: string): HTMLTextAreaElement | null;
  inputValue(id: string, fallback?: string): string;
  textareaValue(id: string, fallback?: string): string;
  selectValue(id: string, fallback?: string): string;
  checkboxValue(id: string, fallback?: boolean): boolean;
  numberValue(id: string, fallback?: number): number;
  firstFile(id: string): File | null;
  focusById(id: string): void;
}

interface AdminEventsApi {
  delegateEvent<T extends Element = Element>(
    root: Document | Element,
    eventName: string,
    selector: string,
    handler: (event: Event, target: T) => void
  ): () => void;
  bindEscape(handler: () => void, root?: Document | HTMLElement): () => void;
}

interface SimpleInitApi {
  init: (...args: unknown[]) => void;
}

interface SimpleRenderApi {
  render: (...args: unknown[]) => string | void;
}

interface AccessControlConfigApi extends SimpleInitApi {
  render(): void;
  switchTab(tabId: string): void;
  updateField(path: string, value: unknown): void;
  saveConfig(): Promise<void>;
  loadConfig(): Promise<void>;
}

interface APISecurityConfigApi {
  init(containerId?: string): void | Promise<void>;
  render(): void;
  switchTab(tabId: string): void;
  updateField(path: string, value: unknown): void;
  saveConfig(): Promise<void>;
  loadConfig(): Promise<void>;
}

interface HTTPSecurityConfigApi {
  init(): void | Promise<void>;
  dispose?(): void;
  render(): void;
  switchTab(tabId: string): void;
  updateField(path: string, value: unknown): void;
  saveConfig(): Promise<void>;
  loadConfig(): Promise<void>;
}

interface TrafficConfigApi {
  init(): void | Promise<void>;
  render(): void;
  switchTab(tabId: string): void;
  saveConfig(): Promise<void>;
}

interface WAFConfigApi {
  init(): void | Promise<void>;
  render(): void;
  switchTab(tabId: string): void;
  updateField(path: string, value: unknown): void;
  saveConfig(): Promise<void>;
}

interface RuleEditorApi {
  init(filePath: string): Promise<void>;
  switchTab(tab: string): Promise<void>;
  saveFile(): Promise<void>;
}

interface JsVectorMapInstance {
  destroy?: () => void;
  updateSize?: () => void;
}

interface JsVectorMapConstructor {
  new (options: Record<string, unknown>): JsVectorMapInstance;
}

interface ChartDatasetLike {
  data: Array<number | string>;
}

interface ChartDataLike {
  labels?: Array<number | string>;
  datasets: ChartDatasetLike[];
}

interface ChartLike {
  data: ChartDataLike;
  update(mode?: string): void;
  destroy(): void;
}

interface ChartStatic {
  new (target: Element | CanvasRenderingContext2D, config: Record<string, unknown>): ChartLike;
  getChart(target: Element | string): ChartLike | undefined;
}

interface EChartsStatic {
  init(target: HTMLElement, theme?: string, opts?: Record<string, unknown>): {
    setOption(option: Record<string, unknown>, opts?: Record<string, unknown>): void;
    resize(): void;
    dispose(): void;
    on(eventName: string, handler: (params: Record<string, unknown>) => void): void;
  };
}

declare const Chart: ChartStatic;
declare function setText(elementId: string, text: string | number): void;
declare function setHTML(elementId: string, html: string): void;
declare function formatNumber(value: number): string;
declare function renderTable(
  id: string,
  data: Record<string, number>,
  options?: {
    showPercent?: boolean;
    isPath?: boolean;
    limit?: number;
    emptyMessage?: string;
    columns?: number;
  }
): void;
declare function initTrafficChart(history: unknown[]): void;
declare function initStatusChart(dist: Record<string, number>): void;
declare function initLatencyChart(buckets: Record<string, number>): void;
declare function initPlatformsChart(userAgents: Record<string, number>): void;
declare function destroyChart(chartVar: string): void;
declare function initAttackVectorChart(vectors: Record<string, number>): void;
declare function initThreatTimeline(historyData: unknown[]): void;
declare function initStatusHealthChart(historyData: unknown[], statusDist: Record<string, number>): void;
declare function createChart(ctxOrId: string | Element | CanvasRenderingContext2D, config: Record<string, unknown>): ChartLike | null;
declare function loadSecurityDashboard(providedStats?: Record<string, unknown>): Promise<void>;
declare function loadAnalyticsDashboard(providedStats?: Record<string, unknown>): void;
declare function loadSystemDashboard(): Promise<void>;
declare function loadWAFDashboardData(): void;
interface Window {
  jsVectorMap?: JsVectorMapConstructor;
  echarts?: EChartsStatic;
  [key: string]: unknown;
}
