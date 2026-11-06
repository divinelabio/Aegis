import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  TextInput,
  NumberInput,
  Button,
  Tag,
  Toggle,
  Select,
  SelectItem,
  InlineNotification,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Pagination,
} from '@carbon/react';
import {
  Document,
  SettingsAdjust,
  Security,
  Layers,
  ArrowLeft,
  Add,
  TrashCan,
  View,
  Misuse,
  CheckmarkOutline,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  StatusToggle,
  SaveActionBar,
  RadioCardGroup,
} from '../components/common';
import { apiService } from '../services/api';
import type {
  NavItemKey,
  AppSecurityConfig,
  AppSecurityUploadProtectionConfig,
  AppSecurityExtensionFilterConfig,
} from '../types';

interface AppSecurityUploadPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

const EXTENSION_CATEGORIES: Record<string, { label: string; extensions: string[] }> = {
  dangerous: {
    label: 'Executables',
    extensions: ['.exe', '.dll', '.bat', '.cmd', '.sh', '.php', '.jsp', '.aspx', '.jar', '.ps1'],
  },
  images: {
    label: 'Web images',
    extensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'],
  },
  documents: {
    label: 'Documents',
    extensions: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
  },
  archives: {
    label: 'Archives',
    extensions: ['.zip', '.rar', '.7z', '.tar', '.gz'],
  },
  macro: {
    label: 'Macro documents',
    extensions: ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf'],
  },
};

const getExtensionCategory = (ext: string): string => {
  for (const group of Object.values(EXTENSION_CATEGORIES)) {
    if (group.extensions.includes(ext.toLowerCase())) {
      return group.label;
    }
  }
  return 'Custom';
};

const bytesToMb = (bytes?: number, fallbackMb: number = 10): number => {
  if (bytes === undefined || !Number.isFinite(bytes) || bytes <= 0) return fallbackMb;
  return Math.max(1, Math.round(bytes / (1024 * 1024)));
};

const mbToBytes = (mb: number): number => {
  return Math.max(1, mb) * 1024 * 1024;
};

export const AppSecurityUploadPage: React.FC<AppSecurityUploadPageProps> = ({ onNavigate }) => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [serverConfig, setServerConfig] = useState<AppSecurityConfig>({ enabled: true });

  const [blockedExtensions, setBlockedExtensions] = useState<string[]>([
    '.exe', '.dll', '.bat', '.cmd', '.sh', '.php', '.jsp', '.aspx', '.jar', '.ps1',
  ]);
  const [newExtInput, setNewExtInput] = useState<string>('');
  const [extInputError, setExtInputError] = useState<string>('');
  const [tableSearch, setTableSearch] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const [uploadEnabled, setUploadEnabled] = useState<boolean>(true);
  const [uploadMode, setUploadMode] = useState<'detect' | 'block' | 'allow'>('detect');
  const [maxFiles, setMaxFiles] = useState<number>(20);
  const [maxFileSizeMb, setMaxFileSizeMb] = useState<number>(10);
  const [maxTotalUploadSizeMb, setMaxTotalUploadSizeMb] = useState<number>(50);
  const [maxFilenameLength, setMaxFilenameLength] = useState<number>(180);
  const [mimePolicy, setMimePolicy] = useState<'validate' | 'allow'>('validate');
  const [inspectFirstBytes, setInspectFirstBytes] = useState<number>(8192);

  const [detectExecutableBytes, setDetectExecutableBytes] = useState<boolean>(true);
  const [detectServerSideCode, setDetectServerSideCode] = useState<boolean>(true);
  const [detectMacroDocuments, setDetectMacroDocuments] = useState<boolean>(true);
  const [detectSvgScript, setDetectSvgScript] = useState<boolean>(true);
  const [detectHtmlUpload, setDetectHtmlUpload] = useState<boolean>(true);
  const [detectPdfExploits, setDetectPdfExploits] = useState<boolean>(true);
  const [detectHighEntropy, setDetectHighEntropy] = useState<boolean>(true);

  const [archiveEnabled, setArchiveEnabled] = useState<boolean>(true);
  const [maxCompressionRatio, setMaxCompressionRatio] = useState<number>(100);
  const [maxExpandedSizeMb, setMaxExpandedSizeMb] = useState<number>(100);
  const [maxArchiveEntries, setMaxArchiveEntries] = useState<number>(512);
  const [blockNestedArchives, setBlockNestedArchives] = useState<boolean>(true);
  const [blockEncryptedArchives, setBlockEncryptedArchives] = useState<boolean>(true);
  const [blockTraversalPaths, setBlockTraversalPaths] = useState<boolean>(true);

  const handleNavigate = (key: NavItemKey) => {
    if (onNavigate) {
      onNavigate(key);
    } else {
      window.location.hash = `#${key}`;
    }
  };

  const populateFromConfig = useCallback((cfg: AppSecurityConfig) => {
    const extFilter = cfg.extension_filter || ({} as AppSecurityExtensionFilterConfig);
    const up = cfg.upload_protection || ({} as AppSecurityUploadProtectionConfig);

    const extensions = up.blocked_extensions && Array.isArray(up.blocked_extensions)
      ? up.blocked_extensions
      : extFilter.blocked_extensions && Array.isArray(extFilter.blocked_extensions)
        ? extFilter.blocked_extensions
        : ['.exe', '.dll', '.bat', '.cmd', '.sh', '.php', '.jsp', '.aspx', '.jar', '.ps1'];
    setBlockedExtensions(extensions);

    setUploadEnabled(up.enabled !== false);
    setUploadMode((up.mode as any) || 'detect');
    setMaxFiles(up.max_files ?? 20);
    setMaxFileSizeMb(bytesToMb(up.max_file_size, 10));
    setMaxTotalUploadSizeMb(bytesToMb(up.max_total_upload_size, 50));
    setMaxFilenameLength(up.max_filename_length ?? 180);
    setMimePolicy((up.mime_policy as any) || 'validate');
    setInspectFirstBytes(up.inspect_first_bytes ?? 8192);

    const content = up.content_rules || {};
    setDetectExecutableBytes(content.detect_executable_bytes !== false);
    setDetectServerSideCode(content.detect_server_side_code !== false);
    setDetectMacroDocuments(content.detect_macro_documents !== false);
    setDetectSvgScript(content.detect_svg_script !== false);
    setDetectHtmlUpload(content.detect_html_upload !== false);
    setDetectPdfExploits(content.detect_pdf_exploits !== false);
    setDetectHighEntropy(content.detect_high_entropy !== false);

    const archive = up.archive_policy || {};
    setArchiveEnabled(archive.enabled !== false);
    setMaxCompressionRatio(archive.max_compression_ratio ?? 100);
    setMaxExpandedSizeMb(bytesToMb(archive.max_expanded_size, 100));
    setMaxArchiveEntries(archive.max_entries ?? 512);
    setBlockNestedArchives(archive.block_nested_archives !== false);
    setBlockEncryptedArchives(archive.block_encrypted_archives !== false);
    setBlockTraversalPaths(archive.block_traversal_paths !== false);
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getAppSecurityConfig();
      if (cfg) {
        setServerConfig(cfg);
        populateFromConfig(cfg);
      }
    } catch (e: any) {
      setNotification({
        type: 'error',
        message: e?.message || 'Failed to load upload security configuration',
      });
    } finally {
      setLoading(false);
    }
  }, [populateFromConfig]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleAddExtension = (extToAdd?: string) => {
    const raw = (extToAdd || newExtInput).trim().toLowerCase();
    if (!raw) return;

    const parts = raw.split(',').map((p) => p.trim()).filter(Boolean);
    const toAdd: string[] = [];
    let err = '';

    for (let part of parts) {
      if (!part.startsWith('.')) {
        part = `.${part}`;
      }
      if (!/^\.[a-z0-9_-]{1,16}$/.test(part)) {
        err = `Invalid extension: "${part}".`;
        break;
      }
      if (!blockedExtensions.includes(part) && !toAdd.includes(part)) {
        toAdd.push(part);
      }
    }

    if (err) {
      setExtInputError(err);
      return;
    }

    if (toAdd.length > 0) {
      setBlockedExtensions((prev) => [...prev, ...toAdd]);
    }
    setNewExtInput('');
    setExtInputError('');
  };

  const handleRemoveExtension = (ext: string) => {
    setBlockedExtensions((prev) => prev.filter((item) => item !== ext));
  };

  const handleAddCategory = (categoryKey: string) => {
    const group = EXTENSION_CATEGORIES[categoryKey];
    if (!group) return;

    const toAdd = group.extensions.filter((ext) => !blockedExtensions.includes(ext));
    if (toAdd.length > 0) {
      setBlockedExtensions((prev) => [...prev, ...toAdd]);
    }
  };

  const filteredExtensions = useMemo(() => {
    const list = blockedExtensions.map((ext) => ({
      extension: ext,
      category: getExtensionCategory(ext),
    }));

    if (!tableSearch) return list;
    const q = tableSearch.toLowerCase();
    return list.filter(
      (item) => item.extension.toLowerCase().includes(q) || item.category.toLowerCase().includes(q)
    );
  }, [blockedExtensions, tableSearch]);

  const pagedExtensions = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredExtensions.slice(start, start + pageSize);
  }, [filteredExtensions, page, pageSize]);

  const isDirty = useMemo(() => {
    const origUp = serverConfig.upload_protection || ({} as AppSecurityUploadProtectionConfig);
    const origExt = serverConfig.extension_filter || ({} as AppSecurityExtensionFilterConfig);
    const origContent = origUp.content_rules || {};
    const origArchive = origUp.archive_policy || {};

    const origBlocked = origUp.blocked_extensions || origExt.blocked_extensions || [];
    if (
      blockedExtensions.length !== origBlocked.length ||
      blockedExtensions.some((ext) => !origBlocked.includes(ext))
    ) {
      return true;
    }

    if (uploadEnabled !== (origUp.enabled !== false)) return true;
    if (uploadMode !== ((origUp.mode as any) || 'detect')) return true;
    if (maxFiles !== (origUp.max_files ?? 20)) return true;
    if (maxFileSizeMb !== bytesToMb(origUp.max_file_size, 10)) return true;
    if (maxTotalUploadSizeMb !== bytesToMb(origUp.max_total_upload_size, 50)) return true;
    if (maxFilenameLength !== (origUp.max_filename_length ?? 180)) return true;
    if (mimePolicy !== ((origUp.mime_policy as any) || 'validate')) return true;
    if (inspectFirstBytes !== (origUp.inspect_first_bytes ?? 8192)) return true;

    if (detectExecutableBytes !== (origContent.detect_executable_bytes !== false)) return true;
    if (detectServerSideCode !== (origContent.detect_server_side_code !== false)) return true;
    if (detectMacroDocuments !== (origContent.detect_macro_documents !== false)) return true;
    if (detectSvgScript !== (origContent.detect_svg_script !== false)) return true;
    if (detectHtmlUpload !== (origContent.detect_html_upload !== false)) return true;
    if (detectPdfExploits !== (origContent.detect_pdf_exploits !== false)) return true;
    if (detectHighEntropy !== (origContent.detect_high_entropy !== false)) return true;

    if (archiveEnabled !== (origArchive.enabled !== false)) return true;
    if (maxCompressionRatio !== (origArchive.max_compression_ratio ?? 100)) return true;
    if (maxExpandedSizeMb !== bytesToMb(origArchive.max_expanded_size, 100)) return true;
    if (maxArchiveEntries !== (origArchive.max_entries ?? 512)) return true;
    if (blockNestedArchives !== (origArchive.block_nested_archives !== false)) return true;
    if (blockEncryptedArchives !== (origArchive.block_encrypted_archives !== false)) return true;
    if (blockTraversalPaths !== (origArchive.block_traversal_paths !== false)) return true;

    return false;
  }, [
    serverConfig,
    blockedExtensions,
    uploadEnabled,
    uploadMode,
    maxFiles,
    maxFileSizeMb,
    maxTotalUploadSizeMb,
    maxFilenameLength,
    mimePolicy,
    inspectFirstBytes,
    detectExecutableBytes,
    detectServerSideCode,
    detectMacroDocuments,
    detectSvgScript,
    detectHtmlUpload,
    detectPdfExploits,
    detectHighEntropy,
    archiveEnabled,
    maxCompressionRatio,
    maxExpandedSizeMb,
    maxArchiveEntries,
    blockNestedArchives,
    blockEncryptedArchives,
    blockTraversalPaths,
  ]);

  const handleReset = () => {
    populateFromConfig(serverConfig);
    setNewExtInput('');
    setExtInputError('');
    setNotification(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);

    try {
      const payload: Partial<AppSecurityConfig> = {
        extension_filter: {
          enabled: true,
          blocked_extensions: blockedExtensions,
        },
        upload_protection: {
          enabled: uploadEnabled,
          mode: uploadMode,
          max_files: maxFiles,
          max_file_size: mbToBytes(maxFileSizeMb),
          max_total_upload_size: mbToBytes(maxTotalUploadSizeMb),
          max_filename_length: maxFilenameLength,
          mime_policy: mimePolicy,
          blocked_extensions: blockedExtensions,
          inspect_first_bytes: inspectFirstBytes,
          content_rules: {
            detect_executable_bytes: detectExecutableBytes,
            detect_server_side_code: detectServerSideCode,
            detect_macro_documents: detectMacroDocuments,
            detect_svg_script: detectSvgScript,
            detect_html_upload: detectHtmlUpload,
            detect_pdf_exploits: detectPdfExploits,
            detect_high_entropy: detectHighEntropy,
          },
          archive_policy: {
            enabled: archiveEnabled,
            max_compression_ratio: maxCompressionRatio,
            max_expanded_size: mbToBytes(maxExpandedSizeMb),
            max_entries: maxArchiveEntries,
            block_nested_archives: blockNestedArchives,
            block_encrypted_archives: blockEncryptedArchives,
            block_traversal_paths: blockTraversalPaths,
          },
        },
      };

      const res = await apiService.saveAppSecurityConfig(payload);
      if (!res.success) {
        throw new Error(res.error || 'Server returned an error saving upload security configuration.');
      }

      setNotification({
        type: 'success',
        message: 'Upload security configuration saved successfully.',
      });
      await loadData();
    } catch (e: any) {
      setNotification({
        type: 'error',
        message: e?.message || 'Failed to save upload security configuration',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        title="Upload security"
        icon={Document}
        action={
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => handleNavigate('app-security')}
          >
            Back to Overview
          </Button>
        }
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.type}
            title={notification.type === 'success' ? 'Success' : notification.type === 'error' ? 'Error' : 'Notice'}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
          />
        </div>
      )}

      <Tabs>
          <TabList aria-label="Upload Security Configuration Areas" contained>
            <Tab renderIcon={Document}>Blocked extensions</Tab>
            <Tab renderIcon={SettingsAdjust}>Upload limits & MIME</Tab>
            <Tab renderIcon={Security}>Deep inspection</Tab>
            <Tab renderIcon={Layers}>Archive guard</Tab>
          </TabList>

          <TabPanels>
            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Blocked file extensions"
              >
                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '16px 20px',
                    marginBottom: '16px',
                  }}
                >
                  <div style={{ display: 'flex', gap: '8px', maxWidth: '520px', marginBottom: '8px' }}>
                    <TextInput
                      id="input-new-extension"
                      labelText="New extension"
                      hideLabel
                      placeholder="e.g. .exe, .sh, .bat"
                      value={newExtInput}
                      onChange={(e) => setNewExtInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          handleAddExtension();
                        }
                      }}
                    />
                    <Button
                      size="md"
                      renderIcon={Add}
                      onClick={() => handleAddExtension()}
                    >
                      Add
                    </Button>
                  </div>

                  {extInputError && (
                    <p style={{ color: 'var(--cds-text-error)', fontSize: '12px', margin: '0 0 8px 0' }}>
                      {extInputError}
                    </p>
                  )}

                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginTop: '10px' }}>
                    <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginRight: '4px' }}>
                      Presets:
                    </span>
                    {Object.entries(EXTENSION_CATEGORIES).map(([key, cat]) => (
                      <Button
                        key={key}
                        size="sm"
                        kind="ghost"
                        onClick={() => handleAddCategory(key)}
                      >
                        + {cat.label}
                      </Button>
                    ))}
                  </div>
                </div>

                <div style={{ background: 'var(--cds-layer-01)', border: '1px solid var(--cds-border-subtle)' }}>
                  <TableToolbar style={{ padding: '0 8px' }}>
                    <TableToolbarContent>
                      <TableToolbarSearch
                        placeholder="Search extensions..."
                        value={tableSearch}
                        onChange={(e: any) => {
                          setTableSearch(e?.target?.value || '');
                          setPage(1);
                        }}
                      />
                      {blockedExtensions.length > 0 && (
                        <Button
                          size="sm"
                          kind="ghost"
                          onClick={() => setBlockedExtensions([])}
                        >
                          Clear all ({blockedExtensions.length})
                        </Button>
                      )}
                    </TableToolbarContent>
                  </TableToolbar>

                  <Table aria-label="Blocked file extensions table">
                    <TableHead>
                      <TableRow>
                        <TableHeader style={{ width: '25%' }}>Extension</TableHeader>
                        <TableHeader style={{ width: '45%' }}>Category</TableHeader>
                        <TableHeader style={{ width: '15%' }}>Policy</TableHeader>
                        <TableHeader style={{ width: '15%', textAlign: 'right' }}>Action</TableHeader>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {pagedExtensions.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={4} style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--cds-text-secondary)' }}>
                            {tableSearch ? 'No matching extensions.' : 'No blocked extensions.'}
                          </TableCell>
                        </TableRow>
                      ) : (
                        pagedExtensions.map(({ extension, category }) => (
                          <TableRow key={extension}>
                            <TableCell style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                              {extension}
                            </TableCell>
                            <TableCell style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                              {category}
                            </TableCell>
                            <TableCell>
                              <Tag type="red" size="sm">
                                Blocked
                              </Tag>
                            </TableCell>
                            <TableCell style={{ textAlign: 'right' }}>
                              <Button
                                kind="ghost"
                                size="sm"
                                hasIconOnly
                                renderIcon={TrashCan}
                                iconDescription={`Remove ${extension}`}
                                onClick={() => handleRemoveExtension(extension)}
                              />
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>

                  <Pagination
                    totalItems={filteredExtensions.length}
                    page={page}
                    pageSize={pageSize}
                    pageSizes={[10, 20, 50]}
                    onChange={({ page: newPage, pageSize: newPageSize }) => {
                      setPage(newPage);
                      setPageSize(newPageSize);
                    }}
                  />
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Upload limits & MIME"
                action={
                  <StatusToggle
                    id="toggle-upload-protection"
                    toggled={uploadEnabled}
                    onToggle={(val) => setUploadEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle upload limits"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--cds-text-primary)',
                      marginBottom: '12px',
                    }}
                  >
                    Mode
                  </label>
                  <RadioCardGroup
                    name="upload-mode-group"
                    valueSelected={uploadMode}
                    onChange={(val) => setUploadMode(val as any)}
                    options={[
                      {
                        value: 'detect',
                        title: 'Audit (detect)',
                        description: 'Log upload violations without blocking.',
                        icon: View,
                      },
                      {
                        value: 'block',
                        title: 'Block',
                        description: 'Block uploads that violate extension, size, or signature policies.',
                        icon: Misuse,
                      },
                      {
                        value: 'allow',
                        title: 'Disabled',
                        description: 'Disable upload inspection.',
                        icon: CheckmarkOutline,
                      },
                    ]}
                  />
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    gap: '20px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                    marginBottom: '20px',
                  }}
                >
                  <NumberInput
                    id="input-max-files"
                    label="Max files per request"
                    min={1}
                    max={100}
                    step={1}
                    value={maxFiles}
                    onChange={(_e, { value }) => setMaxFiles(Number(value) || 20)}
                  />
                  <NumberInput
                    id="input-max-file-size"
                    label="Max file size (MB)"
                    min={1}
                    max={1024}
                    step={1}
                    value={maxFileSizeMb}
                    onChange={(_e, { value }) => setMaxFileSizeMb(Number(value) || 10)}
                  />
                  <NumberInput
                    id="input-max-total-size"
                    label="Total upload limit (MB)"
                    min={1}
                    max={4096}
                    step={5}
                    value={maxTotalUploadSizeMb}
                    onChange={(_e, { value }) => setMaxTotalUploadSizeMb(Number(value) || 50)}
                  />
                  <NumberInput
                    id="input-max-filename-length"
                    label="Max filename length"
                    min={10}
                    max={512}
                    step={10}
                    value={maxFilenameLength}
                    onChange={(_e, { value }) => setMaxFilenameLength(Number(value) || 180)}
                  />
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                    gap: '20px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                  }}
                >
                  <Select
                    id="select-mime-policy"
                    labelText="MIME policy"
                    value={mimePolicy}
                    onChange={(e) => setMimePolicy(e.target.value as any)}
                  >
                    <SelectItem value="validate" text="Strict (verify binary match)" />
                    <SelectItem value="allow" text="Permissive (trust header)" />
                  </Select>

                  <NumberInput
                    id="input-inspect-first-bytes"
                    label="Inspection buffer (bytes)"
                    min={512}
                    max={65536}
                    step={1024}
                    value={inspectFirstBytes}
                    onChange={(_e, { value }) => setInspectFirstBytes(Number(value) || 8192)}
                  />
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Content inspection"
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Executable binary verification
                    </strong>
                    <Toggle
                      id="toggle-detect-executable-bytes"
                      labelText=""
                      hideLabel
                      toggled={detectExecutableBytes}
                      onToggle={(val) => setDetectExecutableBytes(val)}
                      size="sm"
                    />
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Server-side code & web shells
                    </strong>
                    <Toggle
                      id="toggle-detect-server-code"
                      labelText=""
                      hideLabel
                      toggled={detectServerSideCode}
                      onToggle={(val) => setDetectServerSideCode(val)}
                      size="sm"
                    />
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Macro documents inspection
                    </strong>
                    <Toggle
                      id="toggle-detect-macro-documents"
                      labelText=""
                      hideLabel
                      toggled={detectMacroDocuments}
                      onToggle={(val) => setDetectMacroDocuments(val)}
                      size="sm"
                    />
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Scriptable SVG & XSS polyglots
                    </strong>
                    <Toggle
                      id="toggle-detect-svg-script"
                      labelText=""
                      hideLabel
                      toggled={detectSvgScript}
                      onToggle={(val) => setDetectSvgScript(val)}
                      size="sm"
                    />
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Disguised HTML & phishing
                    </strong>
                    <Toggle
                      id="toggle-detect-html-upload"
                      labelText=""
                      hideLabel
                      toggled={detectHtmlUpload}
                      onToggle={(val) => setDetectHtmlUpload(val)}
                      size="sm"
                    />
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Active PDF & embedded exploits
                    </strong>
                    <Toggle
                      id="toggle-detect-pdf-exploits"
                      labelText=""
                      hideLabel
                      toggled={detectPdfExploits}
                      onToggle={(val) => setDetectPdfExploits(val)}
                      size="sm"
                    />
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '14px 20px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      High-entropy & packed payloads
                    </strong>
                    <Toggle
                      id="toggle-detect-high-entropy"
                      labelText=""
                      hideLabel
                      toggled={detectHighEntropy}
                      onToggle={(val) => setDetectHighEntropy(val)}
                      size="sm"
                    />
                  </div>
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Archive protection"
                action={
                  <StatusToggle
                    id="toggle-archive-guard"
                    toggled={archiveEnabled}
                    onToggle={(val) => setArchiveEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle archive protection"
                  />
                }
              >
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    gap: '20px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                    marginBottom: '20px',
                  }}
                >
                  <NumberInput
                    id="input-compression-ratio"
                    label="Max compression ratio"
                    min={10}
                    max={1000}
                    step={10}
                    value={maxCompressionRatio}
                    onChange={(_e, { value }) => setMaxCompressionRatio(Number(value) || 100)}
                  />
                  <NumberInput
                    id="input-expanded-size"
                    label="Max uncompressed size (MB)"
                    min={1}
                    max={1024}
                    step={10}
                    value={maxExpandedSizeMb}
                    onChange={(_e, { value }) => setMaxExpandedSizeMb(Number(value) || 100)}
                  />
                  <NumberInput
                    id="input-max-entries"
                    label="Max archive entries"
                    min={1}
                    max={5000}
                    step={25}
                    value={maxArchiveEntries}
                    onChange={(_e, { value }) => setMaxArchiveEntries(Number(value) || 512)}
                  />
                </div>

                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '16px 20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Block nested archives
                    </strong>
                    <Toggle
                      id="toggle-block-nested"
                      labelText=""
                      hideLabel
                      toggled={blockNestedArchives}
                      onToggle={(val) => setBlockNestedArchives(val)}
                      size="sm"
                    />
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Block encrypted archives
                    </strong>
                    <Toggle
                      id="toggle-block-encrypted"
                      labelText=""
                      hideLabel
                      toggled={blockEncryptedArchives}
                      onToggle={(val) => setBlockEncryptedArchives(val)}
                      size="sm"
                    />
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', maxWidth: '600px' }}>
                    <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                      Block directory traversal (ZipSlip)
                    </strong>
                    <Toggle
                      id="toggle-block-traversal"
                      labelText=""
                      hideLabel
                      toggled={blockTraversalPaths}
                      onToggle={(val) => setBlockTraversalPaths(val)}
                      size="sm"
                    />
                  </div>
                </div>
              </SectionCard>
            </TabPanel>
          </TabPanels>
        </Tabs>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={handleReset}
        onSave={handleSave}
        message="You have unsaved changes"
      />
    </div>
  );
};

export default AppSecurityUploadPage;
