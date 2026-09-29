import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom-v5-compat';
import {
  Alert,
  AlertGroup,
  AlertActionCloseButton,
  AlertVariant,
  Button,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  Divider,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  PageSection,
  Switch,
  TextArea,
  TextInput,
  Title,
  Flex,
  FlexItem,
} from '@patternfly/react-core';
import type { Settings } from './types';
import { api } from './api';

interface Toast {
  key: number;
  title: string;
  variant: AlertVariant;
}

let toastId = 0;

export default function SettingsPage() {
  const navigate = useNavigate();
  const [settings, setSettings] = useState<Settings>({
    rox_endpoint: '',
    rox_api_token: '',
    pull_secret: '',
    ocp_target_version: '',
    ocp_current_version: '',
    skip_tls_verify: true,
    scan_workers: 10,
    auto_regenerate_enabled: false,
    auto_regenerate_schedule: 'daily_midnight',
    auto_regenerate_timezone: 'UTC',
    max_concurrent_pipelines: 2,
  });
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((title: string, variant: AlertVariant) => {
    const key = toastId++;
    setToasts((prev) => [...prev, { key, title, variant }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.key !== key)), 4000);
  }, []);

  const removeToast = useCallback((key: number) => {
    setToasts((prev) => prev.filter((t) => t.key !== key));
  }, []);

  useEffect(() => {
    api.getSettings().then(setSettings).catch(() => {
      toast('Failed to load settings', AlertVariant.danger);
    });
  }, [toast]);

  const update = <K extends keyof Settings>(field: K, value: Settings[K]) =>
    setSettings((prev) => ({ ...prev, [field]: value }));

  const handleSave = async () => {
    try {
      await api.saveSettings(settings);
      toast('Settings saved', AlertVariant.success);
    } catch (e: unknown) {
      toast(`Error: ${e instanceof Error ? e.message : e}`, AlertVariant.danger);
    }
  };

  const handleTest = async () => {
    if (!settings.rox_endpoint || !settings.rox_api_token) {
      toast('Enter Central URL and API Token first', AlertVariant.warning);
      return;
    }
    toast('Testing connection...', AlertVariant.info);
    try {
      const res = await api.testConnection(
        settings.rox_endpoint,
        settings.rox_api_token,
        settings.skip_tls_verify
      );
      if (res.ok) toast('Connected to RHACS Central', AlertVariant.success);
      else toast(`Connection failed: ${res.error || 'unknown'}`, AlertVariant.danger);
    } catch (e: unknown) {
      toast(`Error: ${e instanceof Error ? e.message : e}`, AlertVariant.danger);
    }
  };

  return (
    <>
      <AlertGroup isToast isLiveRegion>
        {toasts.map((t) => (
          <Alert
            key={t.key}
            variant={t.variant}
            title={t.title}
            actionClose={<AlertActionCloseButton onClose={() => removeToast(t.key)} />}
          />
        ))}
      </AlertGroup>

      <PageSection hasBodyWrapper={false} className="pf-v6-u-display-flex pf-v6-u-flex-direction-row pf-v6-u-justify-content-space-between pf-v6-u-align-items-center">
        <Title headingLevel="h1">CVE Analyzer Settings</Title>
        <Button variant="link" onClick={() => navigate('/main/cve-analyzer')}>
          Back to Reports
        </Button>
      </PageSection>
      <Divider component="div" />

      <PageSection hasBodyWrapper={false}>
        <Flex direction={{ default: 'column' }} gap={{ default: 'gapMd' }}>
          <Card>
            <CardTitle>RHACS / StackRox Central</CardTitle>
            <CardBody>
              <Form>
                <FormGroup label="Central URL" fieldId="rox-endpoint">
                  <TextInput
                    id="rox-endpoint"
                    value={settings.rox_endpoint}
                    onChange={(_e, v) => update('rox_endpoint', v)}
                    placeholder="central-rhacs-operator.apps..."
                  />
                </FormGroup>
                <FormGroup label="API Token" fieldId="rox-token">
                  <TextInput
                    id="rox-token"
                    type="password"
                    value={settings.rox_api_token}
                    onChange={(_e, v) => update('rox_api_token', v)}
                    placeholder="eyJhbGci..."
                  />
                </FormGroup>
                <Checkbox
                  id="skip-tls"
                  label="Skip TLS verification (for self-signed certificates)"
                  isChecked={settings.skip_tls_verify}
                  onChange={(_e, checked) => update('skip_tls_verify', checked)}
                />
              </Form>
            </CardBody>
          </Card>

          <Card>
            <CardTitle>Registry Authentication</CardTitle>
            <CardBody>
              <Form>
                <FormGroup label="Pull Secret" fieldId="pull-secret">
                  <TextArea
                    id="pull-secret"
                    value={settings.pull_secret}
                    onChange={(_e, v) => update('pull_secret', v)}
                    placeholder='{"auths":{"registry.redhat.io":{"auth":"..."}}}'
                    resizeOrientation="vertical"
                    rows={5}
                    style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                  />
                </FormGroup>
              </Form>
            </CardBody>
          </Card>

          <Card>
            <CardTitle>OpenShift Cluster</CardTitle>
            <CardBody>
              <Form>
                <FormGroup label="OCP Target Version" fieldId="ocp-target">
                  <TextInput
                    id="ocp-target"
                    value={settings.ocp_target_version}
                    onChange={(_e, v) => update('ocp_target_version', v)}
                    placeholder="4.18.54"
                  />
                </FormGroup>
                <FormGroup label="OCP Current Version" fieldId="ocp-current">
                  <TextInput
                    id="ocp-current"
                    value={settings.ocp_current_version}
                    onChange={(_e, v) => update('ocp_current_version', v)}
                    placeholder="4.18.50"
                  />
                </FormGroup>
              </Form>
            </CardBody>
          </Card>

          <Card>
            <CardTitle>Pipeline</CardTitle>
            <CardBody>
              <Form>
                <FormGroup label="Concurrent Scan Workers" fieldId="scan-workers">
                  <TextInput
                    id="scan-workers"
                    type="number"
                    value={String(settings.scan_workers)}
                    onChange={(_e, v) => update('scan_workers', Math.max(1, Math.min(20, parseInt(v) || 10)))}
                  />
                </FormGroup>
              </Form>
            </CardBody>
          </Card>

          <Card>
            <CardTitle>Auto-Regenerate Reports</CardTitle>
            <CardBody>
              <Form>
                <FormGroup fieldId="auto-regen-toggle">
                  <Switch
                    id="auto-regen-toggle"
                    label={settings.auto_regenerate_enabled ? 'Enabled -- reports regenerate on schedule' : 'Disabled -- reports stay static'}
                    isChecked={settings.auto_regenerate_enabled}
                    onChange={(_e, checked) => update('auto_regenerate_enabled', checked)}
                  />
                </FormGroup>
                {settings.auto_regenerate_enabled && (
                  <>
                    <FormGroup label="Schedule" fieldId="auto-regen-schedule">
                      <FormSelect
                        id="auto-regen-schedule"
                        value={settings.auto_regenerate_schedule}
                        onChange={(_e, v) => update('auto_regenerate_schedule', v)}
                      >
                        <FormSelectOption value="daily_midnight" label="Daily at midnight" />
                        <FormSelectOption value="every_12h" label="Every 12 hours" />
                        <FormSelectOption value="weekly_monday" label="Weekly on Monday" />
                      </FormSelect>
                    </FormGroup>
                    <FormGroup label="Timezone" fieldId="auto-regen-tz">
                      <FormSelect
                        id="auto-regen-tz"
                        value={settings.auto_regenerate_timezone}
                        onChange={(_e, v) => update('auto_regenerate_timezone', v)}
                      >
                        {[
                          'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific',
                          'Europe/London', 'Europe/Berlin', 'Europe/Paris',
                          'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Kolkata',
                          'Australia/Sydney',
                        ].map(tz => (
                          <FormSelectOption key={tz} value={tz} label={tz} />
                        ))}
                      </FormSelect>
                    </FormGroup>
                  </>
                )}
                <FormGroup label="Max Concurrent Pipelines" fieldId="max-concurrent">
                  <TextInput
                    id="max-concurrent"
                    type="number"
                    value={String(settings.max_concurrent_pipelines)}
                    onChange={(_e, v) => update('max_concurrent_pipelines', Math.max(1, Math.min(10, parseInt(v) || 2)))}
                  />
                  <div style={{ fontSize: '.75rem', color: 'var(--pf-t--global--color--subtle)', marginTop: 4 }}>
                    Limits how many reports can regenerate simultaneously to prevent memory exhaustion (1-10)
                  </div>
                </FormGroup>
              </Form>
            </CardBody>
          </Card>

          <Flex gap={{ default: 'gapSm' }}>
            <Button variant="primary" onClick={handleSave}>Save Settings</Button>
            <Button variant="secondary" onClick={handleTest}>Test RHACS Connection</Button>
          </Flex>
        </Flex>
      </PageSection>
    </>
  );
}
