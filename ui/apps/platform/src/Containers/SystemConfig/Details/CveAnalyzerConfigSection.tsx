import { useEffect, useState, useCallback } from 'react';
import {
    Alert,
    Button,
    Card,
    CardBody,
    CardTitle,
    Flex,
    FlexItem,
    Form,
    FormGroup,
    FormSelect,
    FormSelectOption,
    Grid,
    GridItem,
    Spinner,
    Switch,
    TextArea,
    TextInput,
} from '@patternfly/react-core';
import { PencilAltIcon, CheckIcon, TimesIcon } from '@patternfly/react-icons';
import axios from 'services/instance';

const BASE = '/api/v1/cve-analyzer';

interface CveAnalyzerSettings {
    pull_secret: string;
    ocp_target_version: string;
    ocp_current_version: string;
    scan_workers: number;
    auto_regenerate_enabled: boolean;
    auto_regenerate_schedule: string;
    auto_regenerate_timezone: string;
    max_concurrent_pipelines: number;
}

const defaultSettings: CveAnalyzerSettings = {
    pull_secret: '',
    ocp_target_version: '',
    ocp_current_version: '',
    scan_workers: 10,
    auto_regenerate_enabled: false,
    auto_regenerate_schedule: 'daily_midnight',
    auto_regenerate_timezone: 'UTC',
    max_concurrent_pipelines: 2,
};

const timezones = [
    'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific',
    'Europe/London', 'Europe/Berlin', 'Europe/Paris',
    'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Kolkata',
    'Australia/Sydney',
];

export default function CveAnalyzerConfigSection() {
    const [settings, setSettings] = useState<CveAnalyzerSettings>(defaultSettings);
    const [savedSettings, setSavedSettings] = useState<CveAnalyzerSettings>(defaultSettings);
    const [isEditing, setIsEditing] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [saveStatus, setSaveStatus] = useState<'idle' | 'success' | 'error'>('idle');
    const [error, setError] = useState('');

    useEffect(() => {
        axios.get<CveAnalyzerSettings>(`${BASE}/settings`)
            .then((r) => {
                setSettings(r.data);
                setSavedSettings(r.data);
                setError('');
            })
            .catch(() => setError('Failed to load CVE Analyzer settings'))
            .finally(() => setIsLoading(false));
    }, []);

    const update = useCallback(<K extends keyof CveAnalyzerSettings>(field: K, value: CveAnalyzerSettings[K]) => {
        setSettings((prev) => ({ ...prev, [field]: value }));
    }, []);

    const handleSave = async () => {
        setIsSaving(true);
        setSaveStatus('idle');
        try {
            await axios.post(`${BASE}/settings`, settings);
            setSavedSettings(settings);
            setSaveStatus('success');
            setIsEditing(false);
            setTimeout(() => setSaveStatus('idle'), 3000);
        } catch {
            setSaveStatus('error');
        } finally {
            setIsSaving(false);
        }
    };

    const handleCancel = () => {
        setSettings(savedSettings);
        setIsEditing(false);
        setSaveStatus('idle');
    };

    if (isLoading) {
        return <Spinner size="lg" />;
    }

    if (error) {
        return <Alert variant="warning" isInline title={error} />;
    }

    const hasPullSecret = !!settings.pull_secret;

    return (
        <>
            <Flex direction={{ default: 'row' }} spaceItems={{ default: 'spaceItemsMd' }}>
                <FlexItem>
                    {!isEditing ? (
                        <Button
                            variant="link"
                            icon={<PencilAltIcon />}
                            onClick={() => setIsEditing(true)}
                        >
                            Edit
                        </Button>
                    ) : (
                        <Flex spaceItems={{ default: 'spaceItemsSm' }}>
                            <Button
                                variant="primary"
                                icon={<CheckIcon />}
                                onClick={handleSave}
                                isLoading={isSaving}
                                isDisabled={isSaving}
                                size="sm"
                            >
                                Save
                            </Button>
                            <Button
                                variant="link"
                                icon={<TimesIcon />}
                                onClick={handleCancel}
                                isDisabled={isSaving}
                                size="sm"
                            >
                                Cancel
                            </Button>
                        </Flex>
                    )}
                </FlexItem>
                {saveStatus === 'success' && (
                    <FlexItem>
                        <Alert variant="success" isInline isPlain title="Settings saved" />
                    </FlexItem>
                )}
                {saveStatus === 'error' && (
                    <FlexItem>
                        <Alert variant="danger" isInline isPlain title="Failed to save settings" />
                    </FlexItem>
                )}
            </Flex>

            <Grid hasGutter>
                <GridItem sm={12} md={6}>
                    <Card isCompact>
                        <CardTitle>Registry Authentication</CardTitle>
                        <CardBody>
                            {isEditing ? (
                                <Form>
                                    <FormGroup label="Pull Secret" fieldId="cve-pull-secret">
                                        <TextArea
                                            id="cve-pull-secret"
                                            value={settings.pull_secret}
                                            onChange={(_e, v) => update('pull_secret', v)}
                                            placeholder='{"auths":{"registry.redhat.io":{"auth":"..."}}}'
                                            resizeOrientation="vertical"
                                            rows={4}
                                            style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                                        />
                                    </FormGroup>
                                </Form>
                            ) : (
                                <div style={{ fontSize: '.85rem', color: hasPullSecret ? 'var(--pf-t--global--color--status--success--default)' : 'var(--pf-t--global--color--status--warning--default)' }}>
                                    {hasPullSecret ? 'Configured' : 'Not configured'}
                                </div>
                            )}
                        </CardBody>
                    </Card>
                </GridItem>

                <GridItem sm={12} md={6}>
                    <Card isCompact>
                        <CardTitle>OpenShift — CSV Upload Settings</CardTitle>
                        <CardBody>
                            {isEditing ? (
                                <Form>
                                    <FormGroup label="OCP Current Version" fieldId="cve-ocp-current">
                                        <TextInput
                                            id="cve-ocp-current"
                                            value={settings.ocp_current_version}
                                            onChange={(_e, v) => update('ocp_current_version', v)}
                                            placeholder="Auto-detected for local scans"
                                        />
                                    </FormGroup>
                                    <FormGroup label="OCP Target Version" fieldId="cve-ocp-target">
                                        <TextInput
                                            id="cve-ocp-target"
                                            value={settings.ocp_target_version}
                                            onChange={(_e, v) => update('ocp_target_version', v)}
                                            placeholder="Auto-detected for local scans"
                                        />
                                    </FormGroup>
                                    <div style={{ fontSize: '.75rem', color: 'var(--pf-t--global--color--subtle)', marginTop: 4 }}>
                                        Only used for CSV uploads from other clusters
                                    </div>
                                </Form>
                            ) : (
                                <dl style={{ margin: 0, fontSize: '.85rem' }}>
                                    <dt style={{ fontWeight: 600 }}>Current Version</dt>
                                    <dd style={{ marginBottom: 8 }}>{settings.ocp_current_version || 'Auto-detected'}</dd>
                                    <dt style={{ fontWeight: 600 }}>Target Version</dt>
                                    <dd>{settings.ocp_target_version || 'Auto-detected'}</dd>
                                </dl>
                            )}
                        </CardBody>
                    </Card>
                </GridItem>

                <GridItem sm={12} md={6}>
                    <Card isCompact>
                        <CardTitle>Pipeline</CardTitle>
                        <CardBody>
                            {isEditing ? (
                                <Form>
                                    <FormGroup label="Concurrent Scan Workers" fieldId="cve-scan-workers">
                                        <TextInput
                                            id="cve-scan-workers"
                                            type="number"
                                            value={String(settings.scan_workers)}
                                            onChange={(_e, v) => update('scan_workers', Math.max(1, Math.min(20, parseInt(v) || 10)))}
                                        />
                                    </FormGroup>
                                    <FormGroup label="Max Concurrent Pipelines" fieldId="cve-max-concurrent">
                                        <TextInput
                                            id="cve-max-concurrent"
                                            type="number"
                                            value={String(settings.max_concurrent_pipelines)}
                                            onChange={(_e, v) => update('max_concurrent_pipelines', Math.max(1, Math.min(10, parseInt(v) || 2)))}
                                        />
                                    </FormGroup>
                                </Form>
                            ) : (
                                <dl style={{ margin: 0, fontSize: '.85rem' }}>
                                    <dt style={{ fontWeight: 600 }}>Scan Workers</dt>
                                    <dd style={{ marginBottom: 8 }}>{settings.scan_workers}</dd>
                                    <dt style={{ fontWeight: 600 }}>Max Concurrent Pipelines</dt>
                                    <dd>{settings.max_concurrent_pipelines}</dd>
                                </dl>
                            )}
                        </CardBody>
                    </Card>
                </GridItem>

                <GridItem sm={12} md={6}>
                    <Card isCompact>
                        <CardTitle>Auto-Regenerate</CardTitle>
                        <CardBody>
                            {isEditing ? (
                                <Form>
                                    <FormGroup fieldId="cve-auto-regen-toggle">
                                        <Switch
                                            id="cve-auto-regen-toggle"
                                            label={settings.auto_regenerate_enabled ? 'Enabled' : 'Disabled'}
                                            isChecked={settings.auto_regenerate_enabled}
                                            onChange={(_e, checked) => update('auto_regenerate_enabled', checked)}
                                        />
                                    </FormGroup>
                                    {settings.auto_regenerate_enabled && (
                                        <>
                                            <FormGroup label="Schedule" fieldId="cve-auto-regen-schedule">
                                                <FormSelect
                                                    id="cve-auto-regen-schedule"
                                                    value={settings.auto_regenerate_schedule}
                                                    onChange={(_e, v) => update('auto_regenerate_schedule', v)}
                                                >
                                                    <FormSelectOption value="daily_midnight" label="Daily at midnight" />
                                                    <FormSelectOption value="every_12h" label="Every 12 hours" />
                                                    <FormSelectOption value="weekly_monday" label="Weekly on Monday" />
                                                </FormSelect>
                                            </FormGroup>
                                            <FormGroup label="Timezone" fieldId="cve-auto-regen-tz">
                                                <FormSelect
                                                    id="cve-auto-regen-tz"
                                                    value={settings.auto_regenerate_timezone}
                                                    onChange={(_e, v) => update('auto_regenerate_timezone', v)}
                                                >
                                                    {timezones.map((tz) => (
                                                        <FormSelectOption key={tz} value={tz} label={tz} />
                                                    ))}
                                                </FormSelect>
                                            </FormGroup>
                                        </>
                                    )}
                                </Form>
                            ) : (
                                <dl style={{ margin: 0, fontSize: '.85rem' }}>
                                    <dt style={{ fontWeight: 600 }}>Status</dt>
                                    <dd style={{ marginBottom: 8 }}>{settings.auto_regenerate_enabled ? 'Enabled' : 'Disabled'}</dd>
                                    {settings.auto_regenerate_enabled && (
                                        <>
                                            <dt style={{ fontWeight: 600 }}>Schedule</dt>
                                            <dd style={{ marginBottom: 8 }}>{settings.auto_regenerate_schedule}</dd>
                                            <dt style={{ fontWeight: 600 }}>Timezone</dt>
                                            <dd>{settings.auto_regenerate_timezone}</dd>
                                        </>
                                    )}
                                </dl>
                            )}
                        </CardBody>
                    </Card>
                </GridItem>
            </Grid>
        </>
    );
}
