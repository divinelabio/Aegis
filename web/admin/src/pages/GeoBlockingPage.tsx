import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  Grid,
  Column,
  Tile,
  Button,
  Tag,
  Modal,
  Search,
  Checkbox,
  InlineLoading,
  InlineNotification,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Layer,
  ContentSwitcher,
  Switch,
} from '@carbon/react';
import {
  Globe,
  EarthEuropeAfrica,
  EarthAmericas,
  TrashCan,
  Add,
} from '@carbon/icons-react';
import { PageHeader, SaveActionBar, CountryBadge } from '../components/common';
import jsVectorMap from 'jsvectormap';
import 'jsvectormap/dist/maps/world.js';
import 'jsvectormap/dist/jsvectormap.css';
import { apiService } from '../services/api';
import {
  COUNTRIES_MAP,
  REGIONS_MAP,
  getGeoHighlightedCountries,
} from '../data/geoData';
import type { TrafficGeoConfig, NavItemKey } from '../types';

interface GeoBlockingPageProps {
  onNavigate?: (key: NavItemKey) => void;
  theme?: 'g100' | 'g10';
}

export const GeoBlockingPage: React.FC<GeoBlockingPageProps> = ({ onNavigate: _onNavigate, theme }) => {
  const [enabled, setEnabled] = useState<boolean>(true);
  const [mode, setMode] = useState<'blocklist' | 'allowlist'>('blocklist');
  const [selectedCountries, setSelectedCountries] = useState<string[]>([]);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [initialConfig, setInitialConfig] = useState<TrafficGeoConfig | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [modalSearch, setModalSearch] = useState<string>('');
  const [tempCountries, setTempCountries] = useState<Set<string>>(new Set());
  const [tempRegions, setTempRegions] = useState<Set<string>>(new Set());

  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<any>(null);

  const isBlock = mode === 'blocklist';
  const totalActive = selectedCountries.length + selectedRegions.length;

  const highlightedCountries = useMemo(
    () => getGeoHighlightedCountries(selectedCountries, selectedRegions),
    [selectedCountries, selectedRegions]
  );

  const isDark = useMemo(() => {
    if (theme === 'g100') return true;
    if (theme === 'g10') return false;
    if (typeof document !== 'undefined') {
      return Boolean(
        document.querySelector('.cds--g100, .cds--g90') ||
        document.documentElement.getAttribute('data-carbon-theme') === 'g100'
      );
    }
    return false;
  }, [theme]);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const cfg = await apiService.getTrafficGeoConfig();
      if (cfg) {
        setInitialConfig(cfg);
        setEnabled(cfg.enabled !== false);
        const effectiveMode = cfg.mode || ((cfg.allow_countries || []).length > 0 ? 'allowlist' : 'blocklist');
        setMode(effectiveMode);

        const countriesList = (effectiveMode === 'allowlist'
          ? cfg.allow_countries || cfg.countries || []
          : cfg.block_countries || cfg.countries || []).map((c) => c.toUpperCase());
        setSelectedCountries(countriesList);

        const regionsList = (cfg.groups || cfg.regions || []).map((r) => r.replace(/^@/, '').toUpperCase());
        setSelectedRegions(regionsList);
      }
      setIsDirty(false);
    } catch (err) {
      console.error('Failed to load geo config:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleToggleCountry = useCallback((code: string) => {
    setSelectedCountries((prev) =>
      prev.includes(code) ? prev.filter((c) => c !== code) : [...prev, code]
    );
    setIsDirty(true);
  }, []);

  const handleToggleCountryRef = useRef(handleToggleCountry);
  handleToggleCountryRef.current = handleToggleCountry;

  const handleSetMode = (newMode: 'blocklist' | 'allowlist') => {
    setMode(newMode);
    setIsDirty(true);
  };

  const handleRemoveCountry = (code: string) => {
    setSelectedCountries((prev) => prev.filter((c) => c !== code));
    setIsDirty(true);
  };

  const handleRemoveRegion = (code: string) => {
    setSelectedRegions((prev) => prev.filter((r) => r !== code));
    setIsDirty(true);
  };

  useEffect(() => {
    if (isLoading || !mapContainerRef.current) return;

    if (mapInstanceRef.current) {
      try {
        mapInstanceRef.current.destroy();
      } catch {
      }
      mapInstanceRef.current = null;
    }
    mapContainerRef.current.innerHTML = '';

    const color = isBlock ? '#da1e28' : '#ff832b';
    const hoverColor = isBlock ? '#fa4d56' : '#ff9d57';
    const defaultFill = isDark ? '#393939' : '#e0e0e0';
    const defaultStroke = isDark ? '#262626' : '#ffffff';
    const defaultHover = isDark ? '#525252' : '#c6c6c6';

    try {
      const map = new (jsVectorMap as any)({
        selector: mapContainerRef.current,
        map: 'world',
        backgroundColor: 'transparent',
        draggable: true,
        zoomButtons: true,
        zoomOnScroll: false,
        zoomAnimate: true,
        regionStyle: {
          initial: {
            fill: defaultFill,
            stroke: defaultStroke,
            strokeWidth: 0.6,
          },
          hover: {
            fill: defaultHover,
            cursor: 'pointer',
          },
          selected: {
            fill: color,
            stroke: defaultStroke,
            strokeWidth: 0.8,
          },
          selectedHover: {
            fill: hoverColor,
            stroke: defaultStroke,
          },
        },
        selectedRegions: highlightedCountries,
        onRegionClick: (_event: any, code: string) => {
          handleToggleCountryRef.current(code.toUpperCase());
        },
        onRegionTooltipShow: (_event: any, tooltip: any, code: string) => {
          const upper = code.toUpperCase();
          const name = COUNTRIES_MAP[upper] || upper;
          tooltip.text(`${name} (${upper})`);
        },
      });

      mapInstanceRef.current = map;
    } catch (err) {
      console.error('Failed to initialize jsVectorMap:', err);
    }

    return () => {
      if (mapInstanceRef.current) {
        try {
          mapInstanceRef.current.destroy();
        } catch {
        }
        mapInstanceRef.current = null;
      }
    };
  }, [isLoading, isDark]);

  useEffect(() => {
    if (!mapInstanceRef.current) return;
    try {
      const color = isBlock ? '#da1e28' : '#ff832b';
      const hoverColor = isBlock ? '#fa4d56' : '#ff9d57';
      if (mapInstanceRef.current.params?.regionStyle?.selected) {
        mapInstanceRef.current.params.regionStyle.selected.fill = color;
        mapInstanceRef.current.params.regionStyle.selectedHover.fill = hoverColor;
      }
      mapInstanceRef.current.clearSelectedRegions();
      if (highlightedCountries.length > 0) {
        mapInstanceRef.current.setSelectedRegions(highlightedCountries);
      }
    } catch (err) {
      console.error('Failed to dynamically sync map regions:', err);
    }
  }, [highlightedCountries, isBlock]);

  const handleOpenModal = () => {
    setTempCountries(new Set(selectedCountries));
    setTempRegions(new Set(selectedRegions));
    setModalSearch('');
    setIsModalOpen(true);
  };

  const handleToggleTempCountry = (code: string) => {
    const next = new Set(tempCountries);
    if (next.has(code)) next.delete(code);
    else next.add(code);
    setTempCountries(next);
  };

  const handleToggleTempRegion = (code: string) => {
    const next = new Set(tempRegions);
    if (next.has(code)) next.delete(code);
    else next.add(code);
    setTempRegions(next);
  };

  const handleApplyModal = () => {
    setSelectedCountries(Array.from(tempCountries));
    setSelectedRegions(Array.from(tempRegions));
    setIsModalOpen(false);
    setIsDirty(true);
  };

  const handleSaveConfig = async () => {
    setIsSaving(true);
    try {
      const payload: TrafficGeoConfig = {
        ...(initialConfig || {}),
        enabled,
        mode,
        countries: selectedCountries,
        allow_countries: mode === 'allowlist' ? selectedCountries : [],
        block_countries: mode === 'blocklist' ? selectedCountries : [],
        regions: selectedRegions,
        groups: selectedRegions,
        unknown_action: 'allow',
      };

      const ok = await apiService.saveTrafficGeoConfig(payload);
      if (ok) {
        setInitialConfig(payload);
        setIsDirty(false);
        setNotification({
          type: 'success',
          message: 'Configuration saved.',
        });
      } else {
        setNotification({
          type: 'error',
          message: 'Failed to save configuration.',
        });
      }
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: err?.message || 'Save failed.',
      });
    } finally {
      setIsSaving(false);
    }
  };

  const handleReset = () => {
    loadData();
    setNotification(null);
  };

  const filteredModalRegions = useMemo(() => {
    const q = modalSearch.trim().toLowerCase();
    return Object.entries(REGIONS_MAP).filter(([code, name]) => {
      if (!q) return true;
      return code.toLowerCase().includes(q) || name.toLowerCase().includes(q);
    });
  }, [modalSearch]);

  const filteredModalCountries = useMemo(() => {
    const q = modalSearch.trim().toLowerCase();
    return Object.entries(COUNTRIES_MAP).filter(([code, name]) => {
      if (!q) return true;
      return code.toLowerCase().includes(q) || name.toLowerCase().includes(q);
    });
  }, [modalSearch]);

  if (isLoading) {
    return (
      <div style={{ padding: '64px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <InlineLoading description="Loading..." />
      </div>
    );
  }

  return (
    <div style={{ padding: '32px 32px 80px' }}>
      <PageHeader
        title="Geo-blocking"
        icon={Globe}
      />

      {notification && (
        <div style={{ marginBottom: '16px' }}>
          <InlineNotification
            kind={notification.type}
            title={notification.message}
            onClose={() => setNotification(null)}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <Grid fullWidth style={{ padding: 0 }}>
        <Column lg={10} md={5} sm={4}>
          <Tile
            style={{
              padding: '20px',
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              background: 'var(--cds-layer-01)',
              border: '1px solid var(--cds-border-subtle)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontWeight: 600,
                color: 'var(--cds-text-primary)',
                fontSize: '14px',
                marginBottom: '14px',
              }}
            >
              <Globe size={18} />
              <span>World map</span>
            </div>

            <div
              ref={mapContainerRef}
              style={{
                width: '100%',
                height: '460px',
                position: 'relative',
              }}
            />
          </Tile>
        </Column>

        <Column lg={6} md={3} sm={4}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: '100%' }}>
            <Tile
              style={{
                padding: '20px',
                background: 'var(--cds-layer-01)',
                border: '1px solid var(--cds-border-subtle)',
              }}
            >
              <h3 style={{ fontSize: '14px', fontWeight: 600, margin: '0 0 12px', color: 'var(--cds-text-primary)' }}>
                Policy
              </h3>

              <ContentSwitcher
                selectedIndex={isBlock ? 0 : 1}
                onChange={({ name }) => handleSetMode(name as 'blocklist' | 'allowlist')}
                size="md"
              >
                <Switch name="blocklist" text="Block selected" />
                <Switch name="allowlist" text="Allow selected only" />
              </ContentSwitcher>
            </Tile>

            <Tile
              style={{
                padding: '20px',
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                background: 'var(--cds-layer-01)',
                border: '1px solid var(--cds-border-subtle)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '14px',
                }}
              >
                <div>
                  <h3 style={{ fontSize: '14px', fontWeight: 600, margin: '0 0 2px', color: 'var(--cds-text-primary)' }}>
                    Selected zones
                  </h3>
                  <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                    {totalActive === 0
                      ? 'No zones configured'
                      : `${totalActive} ${totalActive === 1 ? 'zone' : 'zones'}`}
                  </span>
                </div>
                <Button kind="tertiary" size="sm" renderIcon={Add} onClick={handleOpenModal}>
                  Manage zones
                </Button>
              </div>

              <div
                style={{
                  flex: 1,
                  minHeight: 0,
                  overflowY: 'auto',
                  maxHeight: '280px',
                  border: '1px solid var(--cds-border-subtle)',
                  background: 'var(--cds-layer-02)',
                }}
              >
                {totalActive > 0 ? (
                  <Table size="sm">
                    <TableHead>
                      <TableRow>
                        <TableHeader>Zone</TableHeader>
                        <TableHeader>Type</TableHeader>
                        <TableHeader style={{ width: '40px' }}></TableHeader>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {selectedRegions.map((code) => (
                        <TableRow key={`reg-${code}`}>
                          <TableCell>
                            <span style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontWeight: 700, marginRight: '8px' }}>
                              {code}
                            </span>
                            <span style={{ fontSize: '13px' }}>{REGIONS_MAP[code] || code}</span>
                          </TableCell>
                          <TableCell>
                            <Tag type="cool-gray" size="sm">Region</Tag>
                          </TableCell>
                          <TableCell>
                            <Button
                              kind="ghost"
                              hasIconOnly
                              size="sm"
                              renderIcon={TrashCan}
                              iconDescription={`Remove ${REGIONS_MAP[code] || code}`}
                              onClick={() => handleRemoveRegion(code)}
                            />
                          </TableCell>
                        </TableRow>
                      ))}

                      {selectedCountries.map((code) => (
                        <TableRow key={`cty-${code}`}>
                          <TableCell>
                            <CountryBadge code={code} style={{ marginRight: '8px' }} />
                            <span style={{ fontSize: '13px' }}>{COUNTRIES_MAP[code] || code}</span>
                          </TableCell>
                          <TableCell>
                            <Tag type="outline" size="sm">Country</Tag>
                          </TableCell>
                          <TableCell>
                            <Button
                              kind="ghost"
                              hasIconOnly
                              size="sm"
                              renderIcon={TrashCan}
                              iconDescription={`Remove ${COUNTRIES_MAP[code] || code}`}
                              onClick={() => handleRemoveCountry(code)}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div
                    style={{
                      padding: '36px 16px',
                      textAlign: 'center',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: '8px',
                      color: 'var(--cds-text-secondary)',
                    }}
                  >
                    <Globe size={28} style={{ color: 'var(--cds-text-helper)' }} />
                    <strong style={{ color: 'var(--cds-text-primary)' }}>No zones selected</strong>
                    <span style={{ fontSize: '12px' }}>Click countries on the map or use Manage zones.</span>
                  </div>
                )}
              </div>
            </Tile>
          </div>
        </Column>
      </Grid>

      <Modal
        open={isModalOpen}
        modalHeading="Select countries and regions"
        primaryButtonText="Apply"
        secondaryButtonText="Cancel"
        onRequestClose={() => setIsModalOpen(false)}
        onRequestSubmit={handleApplyModal}
        size="lg"
      >
        <div style={{ padding: '0 0 16px' }}>
          <div style={{ marginBottom: '16px' }}>
            <Search
              id="geo-modal-search"
              labelText="Search countries and regions"
              placeholder="Search countries or regions..."
              value={modalSearch}
              onChange={(e) => setModalSearch(e.target.value)}
              size="md"
            />
          </div>

          <div style={{ maxHeight: '420px', overflowY: 'auto', paddingRight: '8px' }}>
            {filteredModalRegions.length > 0 && (
              <div style={{ marginBottom: '20px' }}>
                <div
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--cds-text-secondary)',
                    marginBottom: '10px',
                  }}
                >
                  Regions
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                    gap: '10px',
                  }}
                >
                  {filteredModalRegions.map(([code, name]) => {
                    const isChecked = tempRegions.has(code);
                    return (
                      <Layer key={`modal-reg-${code}`}>
                        <Tile
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '10px',
                            padding: '10px 14px',
                            border: isChecked ? '1px solid var(--cds-interactive)' : undefined,
                            cursor: 'pointer',
                          }}
                          onClick={() => handleToggleTempRegion(code)}
                        >
                          <Checkbox
                            id={`modal-chk-reg-${code}`}
                            labelText={`Select ${name} (${code})`}
                            hideLabel
                            checked={isChecked}
                            onChange={() => handleToggleTempRegion(code)}
                          />
                          <span style={{ display: 'inline-flex', alignItems: 'center', color: 'var(--cds-icon-secondary)' }}>
                            {code.includes('EU') || code.includes('EEA') || code.includes('SCHENGEN') || code.includes('DACH') ? (
                              <EarthEuropeAfrica size={20} />
                            ) : code.includes('USMCA') || code.includes('LATAM') ? (
                              <EarthAmericas size={20} />
                            ) : (
                              <Globe size={20} />
                            )}
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                              {name}
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--cds-text-helper)' }}>{code}</div>
                          </div>
                        </Tile>
                      </Layer>
                    );
                  })}
                </div>
              </div>
            )}

            {filteredModalCountries.length > 0 && (
              <div>
                <div
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--cds-text-secondary)',
                    marginBottom: '10px',
                  }}
                >
                  Countries
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
                    gap: '8px',
                  }}
                >
                  {filteredModalCountries.map(([code, name]) => {
                    const isChecked = tempCountries.has(code);
                    return (
                      <Layer key={`modal-cty-${code}`}>
                        <Tile
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '10px',
                            padding: '8px 12px',
                            border: isChecked ? '1px solid var(--cds-interactive)' : undefined,
                            cursor: 'pointer',
                          }}
                          onClick={() => handleToggleTempCountry(code)}
                        >
                          <Checkbox
                            id={`modal-chk-cty-${code}`}
                            labelText={`Select ${name} (${code})`}
                            hideLabel
                            checked={isChecked}
                            onChange={() => handleToggleTempCountry(code)}
                          />
                          <span
                            style={{
                              fontFamily: 'var(--cds-font-mono, monospace)',
                              fontSize: '11px',
                              fontWeight: 700,
                              color: 'var(--cds-text-secondary)',
                              minWidth: '22px',
                            }}
                          >
                            {code}
                          </span>
                          <span style={{ fontSize: '13px', color: 'var(--cds-text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flex: 1 }}>
                            {name}
                          </span>
                        </Tile>
                      </Layer>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </Modal>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={isSaving}
        onReset={handleReset}
        onSave={handleSaveConfig}
        saveLabel="Save changes"
        resetLabel="Reset"
      />
    </div>
  );
};
