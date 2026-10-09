import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { ApiService } from '../services/api';
import { ScanResultData, ScanType } from '../types';
import { useTranslation } from '../i18n';
import { Globe, MessageSquare, QrCode, Shield, Upload, Sparkles, AlertCircle, ArrowRight, Loader2 } from 'lucide-react';
import { ResultPage } from './ResultPage';

export const ScannerPage: React.FC = () => {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const tabParam = (searchParams.get('tab') as ScanType) || 'url';
  const [activeTab, setActiveTab] = useState<ScanType>(tabParam);

  // Input states
  const [urlInput, setUrlInput] = useState('');
  const [messageInput, setMessageInput] = useState('');
  const [contextInput, setContextInput] = useState('sms');
  const [websiteInput, setWebsiteInput] = useState('');
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);

  // Execution states
  const [loading, setLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState(t('scanner.stageValidating'));
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [error, setError] = useState('');
  const [scanResult, setScanResult] = useState<ScanResultData | null>(null);

  useEffect(() => {
    const tab = searchParams.get('tab') as ScanType;
    if (tab && ['url', 'message', 'qr', 'website'].includes(tab)) {
      setActiveTab(tab);
    }
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  }, [searchParams]);

  const handleTabChange = (tab: ScanType) => {
    if (loading) return;
    setActiveTab(tab);
    setSearchParams({ tab });
    setError('');
  };

  const handleQrFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 5 * 1024 * 1024) {
        setError(t('scanner.qrSizeError'));
        return;
      }
      setQrFile(file);
      setQrPreview(URL.createObjectURL(file));
      setError('');
    }
  };

  // Progressive 3-second security scanning pipeline
  const runProgressiveScan = async (scanPromise: Promise<ScanResultData>, stages: string[]) => {
    setLoading(true);
    setError('');
    setScanResult(null);
    setLoadingProgress(10);
    setLoadingStage(stages[0]);

    const stageTimeouts: Array<ReturnType<typeof setTimeout>> = [
      setTimeout(() => {
        setLoadingProgress(35);
        setLoadingStage(stages[1]);
      }, 750),
      setTimeout(() => {
        setLoadingProgress(70);
        setLoadingStage(stages[2]);
      }, 1650),
      setTimeout(() => {
        setLoadingProgress(92);
        setLoadingStage(stages[3]);
      }, 2500)
    ];

    try {
      // Guarantee at least 3000ms minimum scan execution time
      const [result] = await Promise.all([
        scanPromise,
        new Promise((resolve) => setTimeout(resolve, 3000))
      ]);

      setLoadingProgress(100);
      setLoadingStage('Finalizing calibrated threat assessment & evidence audit...');
      
      // Brief smooth transition before displaying verdict
      await new Promise((resolve) => setTimeout(resolve, 250));
      setScanResult(result);
    } catch (err: any) {
      stageTimeouts.forEach(clearTimeout);
      const msg = err.response?.data?.error?.message || err.message || 'Scan request failed.';
      setError(msg);
    } finally {
      setLoading(false);
      setLoadingProgress(0);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setError('');

    try {
      if (activeTab === 'url') {
        if (!urlInput.trim()) {
          setError(t('scanner.errorUrlRequired'));
          return;
        }
        const stages = [
          'Validating URL syntax & DNS resolution boundaries...',
          'Extracting 31 lexical, structural & IP-host dimensions...',
          'Evaluating url-phishing-2.0.0 XGBoost & Platt calibration...',
          'Arbitrating multi-evidence signals & risk metrics...'
        ];
        await runProgressiveScan(ApiService.scanUrl(urlInput.trim()), stages);
      } else if (activeTab === 'message') {
        if (!messageInput.trim()) {
          setError(t('scanner.errorMessageRequired'));
          return;
        }
        const stages = [
          'Tokenizing text payload & scanning embedded links...',
          'Extracting 10,000 TF-IDF word/char n-grams & intent cues...',
          'Evaluating text-scam-2.0.0 calibrated probability engine...',
          'Synthesizing social engineering evidence signals...'
        ];
        await runProgressiveScan(ApiService.scanMessage(messageInput.trim(), contextInput), stages);
      } else if (activeTab === 'qr') {
        if (!qrFile) {
          setError(t('scanner.errorQrRequired'));
          return;
        }
        const stages = [
          'Validating MIME image format & in-memory matrix allocation...',
          'Decoding QR binary matrix payload with jsQR AST engine...',
          'Routing extracted payload to URL ML detector...',
          'Synthesizing unified forensic evidence report...'
        ];
        await runProgressiveScan(ApiService.scanQr(qrFile), stages);
      } else {
        if (!websiteInput.trim()) {
          setError(t('scanner.errorWebsiteRequired'));
          return;
        }
        const stages = [
          'Executing SSRF private IP validation & RFC 1918 checks...',
          'Fetching sandboxed HTML & tracing multi-hop redirects...',
          'Inspecting DOM password forms & third-party actions...',
          'Aggregating brand spoofing & credential harvesting indicators...'
        ];
        await runProgressiveScan(ApiService.scanWebsite(websiteInput.trim()), stages);
      }
    } catch (err: any) {
      const msg = err.response?.data?.error?.message || err.message || 'Scan request failed.';
      setError(msg);
    }
  };

  // Preset sample test lures
  const fillPreset = (type: string) => {
    setError('');
    if (type === 'phish_url') {
      setUrlInput('http://192.168.1.1/paypal-account-verification-alert99.tk/login.php');
      setActiveTab('url');
      setSearchParams({ tab: 'url' });
    } else if (type === 'benign_url') {
      setUrlInput('https://www.google.com/search?q=cybersecurity+defense');
      setActiveTab('url');
      setSearchParams({ tab: 'url' });
    } else if (type === 'bank_scam_sms') {
      setMessageInput('URGENT: Your Wells Fargo account has been suspended! Verify your credentials immediately at http://wellsfargo-verify-login.xyz to restore access.');
      setContextInput('sms');
      setActiveTab('message');
      setSearchParams({ tab: 'message' });
    } else if (type === 'lottery_scam') {
      setMessageInput('CONGRATULATIONS! You won $1,000,000 in the International Mobile Lottery. Send $500 processing fee via Bitcoin or UPI to claim prize.');
      setContextInput('email');
      setActiveTab('message');
      setSearchParams({ tab: 'message' });
    } else if (type === 'website_safe') {
      setWebsiteInput('https://example.com');
      setActiveTab('website');
      setSearchParams({ tab: 'website' });
    }
  };

  if (scanResult) {
    return (
      <ResultPage
        result={scanResult}
        onNewScan={() => {
          setScanResult(null);
          setUrlInput('');
          setMessageInput('');
          setWebsiteInput('');
          setQrFile(null);
          setQrPreview(null);
        }}
      />
    );
  }

  const tabConfigs = [
    { id: 'url', label: t('scanner.tabUrl'), icon: <Globe className="w-4 h-4 text-cyan-400" /> },
    { id: 'message', label: t('scanner.tabMessage'), icon: <MessageSquare className="w-4 h-4 text-purple-400" /> },
    { id: 'qr', label: t('scanner.tabQr'), icon: <QrCode className="w-4 h-4 text-amber-400" /> },
    { id: 'website', label: t('scanner.tabWebsite'), icon: <Shield className="w-4 h-4 text-emerald-400" /> },
  ];

  return (
    <div className="max-w-4xl mx-auto py-8 space-y-8">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          {t('scanner.title')}
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto leading-relaxed">
          {t('scanner.subtitle')}
        </p>
      </div>

      {/* Preset Test Cases Toolbar */}
      <div className="p-3.5 rounded-xl bg-[#0f172a] border border-[#1e293b] flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 font-mono font-semibold">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>{t('scanner.testScenarios')}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => fillPreset('phish_url')}
            className="px-2.5 py-1 rounded-md bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetPhishUrl')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('benign_url')}
            className="px-2.5 py-1 rounded-md bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetBenignUrl')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('bank_scam_sms')}
            className="px-2.5 py-1 rounded-md bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 border border-amber-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetBankSms')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('lottery_scam')}
            className="px-2.5 py-1 rounded-md bg-purple-950/40 hover:bg-purple-900/60 text-purple-300 border border-purple-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetLotteryScam')}
          </button>
          <button
            type="button"
            onClick={() => fillPreset('website_safe')}
            className="px-2.5 py-1 rounded-md bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/40 text-[11px] font-mono transition"
          >
            {t('scanner.presetBenignDomain')}
          </button>
        </div>
      </div>

      {/* Main Scanner Card */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl shadow-xl overflow-hidden">
        {/* Modality Tabs */}
        <div className="grid grid-cols-2 md:grid-cols-4 border-b border-[#1e293b] bg-[#0b0f19]">
          {tabConfigs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => handleTabChange(tab.id as ScanType)}
                className={`py-3.5 px-3 text-left border-b-2 transition-colors flex items-center justify-start ${
                  isActive
                    ? 'border-cyan-400 bg-[#0f172a]'
                    : 'border-transparent hover:bg-[#131d33]'
                }`}
              >
                <div className="flex items-center gap-2">
                  {tab.icon}
                  <span className={`text-xs font-bold ${isActive ? 'text-white' : 'text-slate-400'}`}>
                    {tab.label}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Scanner Form Body */}
        <form onSubmit={handleScan} className="p-6 sm:p-8 space-y-6">
          {error && (
            <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-start gap-3">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">{t('scanner.validationError')} </span>
                <span>{error}</span>
              </div>
            </div>
          )}

          {/* TAB 1: URL */}
          {activeTab === 'url' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 font-mono">
                  {t('scanner.urlLabel')}
                </label>
                <input
                  type="text"
                  disabled={loading}
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder={t('scanner.urlPlaceholder')}
                  className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl px-4 py-3.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono disabled:opacity-60 disabled:cursor-not-allowed"
                />
              </div>
            </div>
          )}

          {/* TAB 2: Message / Email */}
          {activeTab === 'message' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                  {t('scanner.msgLabel')}
                </label>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400 font-mono">{t('scanner.msgChannel')}</span>
                  <select
                    disabled={loading}
                    value={contextInput}
                    onChange={(e) => setContextInput(e.target.value)}
                    className="bg-[#070a12] border border-[#1e293b] rounded-lg px-2.5 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    <option value="sms">{t('scanner.msgChannelSms')}</option>
                    <option value="email">{t('scanner.msgChannelEmail')}</option>
                    <option value="chat">{t('scanner.msgChannelChat')}</option>
                    <option value="social">{t('scanner.msgChannelSocial')}</option>
                  </select>
                </div>
              </div>
              <textarea
                disabled={loading}
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                rows={5}
                placeholder={t('scanner.msgPlaceholder')}
                className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl p-4 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-400 font-sans leading-relaxed disabled:opacity-60 disabled:cursor-not-allowed"
              />
            </div>
          )}

          {/* TAB 3: QR Code */}
          {activeTab === 'qr' && (
            <div className="space-y-4">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                {t('scanner.qrLabel')}
              </label>
              <div className={`border-2 border-dashed border-[#1e293b] rounded-xl p-8 text-center transition bg-[#070a12] relative ${loading ? 'opacity-60 cursor-not-allowed' : 'hover:border-amber-400/50 cursor-pointer'}`}>
                <input
                  type="file"
                  disabled={loading}
                  accept="image/png,image/jpeg,image/webp"
                  onChange={handleQrFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
                />
                {qrPreview ? (
                  <div className="space-y-3 flex flex-col items-center">
                    <img src={qrPreview} alt="QR Preview" className="w-32 h-32 object-contain rounded-lg border border-[#1e293b] p-1.5 bg-white shadow" />
                    <div className="text-xs font-mono text-amber-400 font-bold">
                      {qrFile?.name} ({(qrFile!.size / 1024).toFixed(1)} KB)
                    </div>
                    <span className="text-[11px] text-slate-400">{t('scanner.qrReplace')}</span>
                  </div>
                ) : (
                  <div className="space-y-2 flex flex-col items-center">
                    <Upload className="w-8 h-8 text-amber-400 mb-1" />
                    <span className="text-xs sm:text-sm font-semibold text-slate-200">
                      {t('scanner.qrDropzone')}
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">
                      {t('scanner.qrLimit')}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: Website Analyzer */}
          {activeTab === 'website' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 font-mono">
                  {t('scanner.webLabel')}
                </label>
                <input
                  type="text"
                  disabled={loading}
                  value={websiteInput}
                  onChange={(e) => setWebsiteInput(e.target.value)}
                  placeholder={t('scanner.webPlaceholder')}
                  className="w-full bg-[#070a12] border border-[#1e293b] rounded-xl px-4 py-3.5 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-400 font-mono disabled:opacity-60 disabled:cursor-not-allowed"
                />
              </div>
            </div>
          )}

          {/* Active 3-Second Scanning Progress Telemetry */}
          {loading && (
            <div className="space-y-2 p-4 rounded-xl bg-[#070c18] border border-cyan-800/60 shadow-lg shadow-cyan-950/30">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyan-300 flex items-center gap-2 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                  <span>{loadingStage}</span>
                </span>
                <span className="text-cyan-400 font-bold bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/80">
                  {loadingProgress}%
                </span>
              </div>

              {/* Glowing High-Precision Progress Bar */}
              <div className="h-2 w-full bg-[#0b1220] rounded-full overflow-hidden border border-[#1e293b] p-0.5">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 rounded-full transition-all duration-500 ease-out shadow-sm shadow-cyan-400"
                  style={{ width: `${loadingProgress}%` }}
                />
              </div>
            </div>
          )}

          {/* Submit Action */}
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-t border-[#1e293b]">
            <div className="text-[11px] text-slate-400 font-mono">
              {loading && (
                <span className="text-cyan-400 flex items-center gap-1.5 font-semibold">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Executing 3.0s Calibrated Evidence Audit...</span>
                </span>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full sm:w-auto px-7 py-3.5 rounded-xl font-bold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-lg transition-all transform ${
                loading
                  ? 'bg-gradient-to-r from-cyan-700 via-cyan-600 to-blue-700 text-white cursor-wait shadow-cyan-500/20 ring-2 ring-cyan-400/40 animate-pulse'
                  : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-600/20 hover:-translate-y-0.5 active:translate-y-0 cursor-pointer'
              }`}
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-200" />
                  <span>Running Security Analysis... ({loadingProgress}%)</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>{t('scanner.btnAnalyze')}</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
