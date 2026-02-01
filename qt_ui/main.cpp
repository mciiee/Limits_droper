#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QDoubleSpinBox>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHash>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QSpinBox>
#include <QSet>
#include <QString>
#include <QVBoxLayout>

#include <cinttypes>
#include <cmath>
#include <cstdint>

namespace {

constexpr std::uint32_t kMsrPkgPowerLimit = 0x610;
constexpr std::uint32_t kMchbarPlOffset = 0x59A0;

std::uint64_t apply_pl_units(std::uint64_t cur, std::uint16_t pl1_units, std::uint16_t pl2_units) {
    std::uint32_t lo = static_cast<std::uint32_t>(cur & 0xffffffffu);
    std::uint32_t hi = static_cast<std::uint32_t>(cur >> 32);

    lo = (lo & ~0x7FFFu) | (static_cast<std::uint32_t>(pl1_units) & 0x7FFFu);
    hi = (hi & ~0x7FFFu) | (static_cast<std::uint32_t>(pl2_units) & 0x7FFFu);

    return (static_cast<std::uint64_t>(hi) << 32) | lo;
}

QString hex64(std::uint64_t v) {
    return QString("0x%1").arg(v, 16, 16, QLatin1Char('0'));
}

QString units_to_text(std::uint16_t units, double unit_watts) {
    double watts = static_cast<double>(units) * unit_watts;
    return QString("units %1 (%2 W)").arg(units).arg(watts, 0, 'f', 2);
}

struct CpuInfo {
    QString vendor;
    QString model_name;
    QString family;
    QString model;
    QString stepping;
    QString microcode;
    QString cache_size;
    int logical_cpus = 0;
    int packages = 0;
    int physical_cores = 0;
    double min_mhz = 0.0;
    double max_mhz = 0.0;
};

QString read_text_file(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }
    return QString::fromLocal8Bit(file.readAll()).trimmed();
}

double read_khz_to_mhz(const QString &path) {
    QString text = read_text_file(path);
    bool ok = false;
    qlonglong khz = text.toLongLong(&ok);
    if (!ok || khz <= 0) {
        return 0.0;
    }
    return static_cast<double>(khz) / 1000.0;
}

CpuInfo read_cpu_info() {
    CpuInfo info;
    QString data = read_text_file("/proc/cpuinfo");
    if (data.isEmpty()) {
        return info;
    }

    QStringList lines = data.split('\n');
    bool first = true;
    int pkg_id = -1;
    int core_id = -1;
    QSet<int> packages;
    QSet<QString> cores;

    auto flush_core = [&]() {
        if (pkg_id >= 0 && core_id >= 0) {
            packages.insert(pkg_id);
            cores.insert(QString("%1:%2").arg(pkg_id).arg(core_id));
        }
        pkg_id = -1;
        core_id = -1;
    };

    for (const QString &line : lines) {
        if (line.isEmpty()) {
            continue;
        }
        int idx = line.indexOf(':');
        if (idx <= 0) {
            continue;
        }
        QString key = line.left(idx).trimmed();
        QString value = line.mid(idx + 1).trimmed();

        if (key == "processor") {
            info.logical_cpus += 1;
            flush_core();
            continue;
        }
        if (key == "physical id") {
            bool ok = false;
            int v = value.toInt(&ok);
            if (ok) {
                pkg_id = v;
            }
            continue;
        }
        if (key == "core id") {
            bool ok = false;
            int v = value.toInt(&ok);
            if (ok) {
                core_id = v;
            }
            continue;
        }

        if (first) {
            if (key == "vendor_id") {
                info.vendor = value;
            } else if (key == "model name") {
                info.model_name = value;
            } else if (key == "cpu family") {
                info.family = value;
            } else if (key == "model") {
                info.model = value;
            } else if (key == "stepping") {
                info.stepping = value;
            } else if (key == "microcode") {
                info.microcode = value;
            } else if (key == "cache size") {
                info.cache_size = value;
            }
        }
    }
    flush_core();

    if (!packages.isEmpty()) {
        info.packages = packages.size();
    }
    if (!cores.isEmpty()) {
        info.physical_cores = cores.size();
    }

    info.min_mhz = read_khz_to_mhz("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
    info.max_mhz = read_khz_to_mhz("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");

    if (info.packages == 0 && info.logical_cpus > 0) {
        info.packages = 1;
    }
    if (info.physical_cores == 0 && info.logical_cpus > 0) {
        info.physical_cores = 0;
    }

    return info;
}

double read_current_mhz_for_cpu(int cpu) {
    QString base = QString("/sys/devices/system/cpu/cpu%1/cpufreq/").arg(cpu);
    double mhz = read_khz_to_mhz(base + "scaling_cur_freq");
    if (mhz <= 0.0) {
        mhz = read_khz_to_mhz(base + "cpuinfo_cur_freq");
    }
    return mhz;
}

QList<int> parse_cpu_list(const QString &list) {
    QList<int> out;
    if (list.isEmpty()) {
        return out;
    }
    const QStringList parts = list.split(',', Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        bool ok = false;
        int cpu = part.trimmed().toInt(&ok);
        if (ok) {
            out.append(cpu);
        }
    }
    return out;
}

QString format_mhz_stats(const QList<int> &cpus) {
    if (cpus.isEmpty()) {
        return "-";
    }
    double sum = 0.0;
    double minv = 0.0;
    double maxv = 0.0;
    int count = 0;
    for (int cpu : cpus) {
        double mhz = read_current_mhz_for_cpu(cpu);
        if (mhz <= 0.0) {
            continue;
        }
        if (count == 0) {
            minv = mhz;
            maxv = mhz;
        } else {
            if (mhz < minv) minv = mhz;
            if (mhz > maxv) maxv = mhz;
        }
        sum += mhz;
        count++;
    }
    if (count == 0) {
        return "-";
    }
    double avg = sum / count;
    return QString("avg %1 (min %2 / max %3)")
        .arg(avg, 0, 'f', 0)
        .arg(minv, 0, 'f', 0)
        .arg(maxv, 0, 'f', 0);
}

struct ReadState {
    int power_unit = 0;
    double unit_watts = 0.0;
    std::uint64_t msr = 0;
    std::uint64_t mmio = 0;
    bool core_type_supported = false;
    QString p_cpus;
    QString e_cpus;
    QString u_cpus;
    bool p_ratio_valid = false;
    bool e_ratio_valid = false;
    int p_ratio = 0;
    int e_ratio = 0;
    bool p_ratio_cur_valid = false;
    bool e_ratio_cur_valid = false;
    int p_ratio_cur = 0;
    int e_ratio_cur = 0;
    bool core_uv_valid = false;
    double core_uv_mv = 0.0;
    QString core_uv_raw;
};

} // namespace

class HelperBackend {
public:
    HelperBackend() : helper_path_(resolve_helper_path()) {}

    bool helper_available(QString *err) const {
        QFileInfo info(helper_path_);
        if (!info.exists()) {
            if (err) {
                *err = QString("Helper not found at %1. Install to /usr/local/bin, or set LIMITS_HELPER_PATH and update the polkit policy path.")
                           .arg(helper_path_);
            }
            return false;
        }
        if (!info.isExecutable()) {
            if (err) {
                *err = QString("Helper is not executable: %1").arg(helper_path_);
            }
            return false;
        }
        return true;
    }

    bool read_state(ReadState &state, QString *err) const {
        QString out;
        QString err_out;
        if (!run_pkexec({"--read"}, &out, &err_out)) {
            if (err) {
                *err = err_out.isEmpty() ? "Failed to run helper" : err_out;
            }
            return false;
        }
        return parse_state(out, state, err);
    }

    bool write_msr(std::uint64_t val, QString *err) const {
        return run_simple({"--write-msr", hex64(val)}, err);
    }

    bool write_mmio(std::uint64_t val, QString *err) const {
        return run_simple({"--write-mmio", hex64(val)}, err);
    }

    bool set_p_ratio(int ratio, QString *err) const {
        return run_simple({"--set-p-ratio", QString::number(ratio)}, err);
    }

    bool set_e_ratio(int ratio, QString *err) const {
        return run_simple({"--set-e-ratio", QString::number(ratio)}, err);
    }

    bool set_pe_ratio(int ratio_p, int ratio_e, QString *err) const {
        return run_simple({"--set-pe-ratio", QString::number(ratio_p), QString::number(ratio_e)}, err);
    }

    bool set_all_ratio(int ratio, QString *err) const {
        return run_simple({"--set-all-ratio", QString::number(ratio)}, err);
    }

    bool set_core_uv(double mv, QString *err) const {
        return run_simple({"--set-core-uv", QString::number(mv, 'f', 3)}, err);
    }

private:
    QString resolve_helper_path() const {
        QString env = qEnvironmentVariable("LIMITS_HELPER_PATH");
        if (!env.isEmpty()) {
            return env;
        }
        QString local = QCoreApplication::applicationDirPath() + "/limits_helper";
        if (QFileInfo::exists(local)) {
            return local;
        }
        return QStringLiteral("/usr/local/bin/limits_helper");
    }

    bool run_simple(const QStringList &args, QString *err) const {
        QString out;
        QString err_out;
        if (!run_pkexec(args, &out, &err_out)) {
            if (err) {
                *err = err_out.isEmpty() ? "Failed to run helper" : err_out;
            }
            return false;
        }
        return true;
    }

    bool run_pkexec(const QStringList &args, QString *out, QString *err) const {
        QProcess proc;
        proc.setProgram("pkexec");
        QStringList full_args;
        full_args << helper_path_;
        full_args << args;
        proc.setArguments(full_args);
        proc.start();

        if (!proc.waitForFinished(-1)) {
            if (err) {
                *err = "Helper timed out.";
            }
            return false;
        }

        if (out) {
            *out = QString::fromLocal8Bit(proc.readAllStandardOutput());
        }
        QString err_text = QString::fromLocal8Bit(proc.readAllStandardError());

        if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
            if (err) {
                if (!err_text.isEmpty()) {
                    *err = err_text.trimmed();
                } else {
                    *err = QString("Helper failed (exit %1)").arg(proc.exitCode());
                }
            }
            return false;
        }

        if (err) {
            *err = err_text.trimmed();
        }
        return true;
    }

    bool parse_state(const QString &out, ReadState &state, QString *err) const {
        QStringList lines = out.split('\n', Qt::SkipEmptyParts);
        QHash<QString, QString> values;
        for (const QString &line : lines) {
            int idx = line.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            QString key = line.left(idx).trimmed();
            QString value = line.mid(idx + 1).trimmed();
            values.insert(key, value);
        }

        bool ok = false;
        state.power_unit = values.value("POWER_UNIT").toInt(&ok);
        if (!ok) {
            if (err) {
                *err = "Missing POWER_UNIT from helper.";
            }
            return false;
        }

        state.unit_watts = values.value("UNIT_WATTS").toDouble(&ok);
        if (!ok) {
            if (err) {
                *err = "Missing UNIT_WATTS from helper.";
            }
            return false;
        }

        state.msr = values.value("MSR").toULongLong(&ok, 0);
        if (!ok) {
            if (err) {
                *err = "Missing MSR value from helper.";
            }
            return false;
        }

        state.mmio = values.value("MMIO").toULongLong(&ok, 0);
        if (!ok) {
            if (err) {
                *err = "Missing MMIO value from helper.";
            }
            return false;
        }

        state.core_type_supported = values.value("CORE_TYPE_SUPPORTED").toInt(&ok) == 1;
        state.p_cpus = values.value("P_CPUS");
        state.e_cpus = values.value("E_CPUS");
        state.u_cpus = values.value("U_CPUS");
        state.p_ratio_valid = values.value("P_RATIO_VALID").toInt(&ok) == 1;
        state.e_ratio_valid = values.value("E_RATIO_VALID").toInt(&ok) == 1;
        state.p_ratio_cur_valid = values.value("P_RATIO_CUR_VALID").toInt(&ok) == 1;
        state.e_ratio_cur_valid = values.value("E_RATIO_CUR_VALID").toInt(&ok) == 1;

        int ratio = values.value("P_RATIO_TARGET").toInt(&ok);
        state.p_ratio = ok ? ratio : 0;
        ratio = values.value("E_RATIO_TARGET").toInt(&ok);
        state.e_ratio = ok ? ratio : 0;

        ratio = values.value("P_RATIO_CUR").toInt(&ok);
        state.p_ratio_cur = ok ? ratio : 0;
        ratio = values.value("E_RATIO_CUR").toInt(&ok);
        state.e_ratio_cur = ok ? ratio : 0;

        state.core_uv_valid = values.value("CORE_UV_VALID").toInt(&ok) == 1;
        state.core_uv_mv = values.value("CORE_UV_MV").toDouble(&ok);
        state.core_uv_raw = values.value("CORE_UV_RAW");

        return true;
    }

    QString helper_path_;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow() {
        setWindowTitle("Limits UI");

        auto *central = new QWidget();
        auto *root = new QVBoxLayout();

        auto *title = new QLabel("Limits UI (MSR 0x610 + MCHBAR 0x59A0)");
        QFont title_font = title->font();
        title_font.setPointSize(title_font.pointSize() + 2);
        title_font.setBold(true);
        title->setFont(title_font);
        root->addWidget(title);

        cpu_group_ = new QGroupBox("CPU info");
        auto *cpu_layout = new QFormLayout();

        cpu_vendor_ = new QLabel("-");
        cpu_model_name_ = new QLabel("-");
        cpu_family_model_ = new QLabel("-");
        cpu_microcode_ = new QLabel("-");
        cpu_cache_ = new QLabel("-");
        cpu_logical_ = new QLabel("-");
        cpu_physical_ = new QLabel("-");
        cpu_packages_ = new QLabel("-");
        cpu_freq_ = new QLabel("-");
        cpu_p_count_ = new QLabel("-");
        cpu_e_count_ = new QLabel("-");
        cpu_p_mhz_ = new QLabel("-");
        cpu_e_mhz_ = new QLabel("-");

        cpu_layout->addRow("Vendor", cpu_vendor_);
        cpu_layout->addRow("Model", cpu_model_name_);
        cpu_layout->addRow("Family/Model/Stepping", cpu_family_model_);
        cpu_layout->addRow("Microcode", cpu_microcode_);
        cpu_layout->addRow("Cache", cpu_cache_);
        cpu_layout->addRow("Logical CPUs", cpu_logical_);
        cpu_layout->addRow("Physical cores", cpu_physical_);
        cpu_layout->addRow("Packages", cpu_packages_);
        cpu_layout->addRow("Min/Max MHz", cpu_freq_);
        cpu_layout->addRow("P cores (detected)", cpu_p_count_);
        cpu_layout->addRow("E cores (detected)", cpu_e_count_);
        cpu_layout->addRow("P cores MHz", cpu_p_mhz_);
        cpu_layout->addRow("E cores MHz", cpu_e_mhz_);

        cpu_group_->setLayout(cpu_layout);
        root->addWidget(cpu_group_);

        status_group_ = new QGroupBox("Status");
        auto *status_layout = new QFormLayout();

        unit_label_ = new QLabel("unknown");
        status_layout->addRow("Power unit", unit_label_);

        msr_raw_ = make_readonly_line();
        mmio_raw_ = make_readonly_line();

        msr_pl1_ = new QLabel("-");
        msr_pl2_ = new QLabel("-");
        mmio_pl1_ = new QLabel("-");
        mmio_pl2_ = new QLabel("-");
        p_cpus_ = new QLabel("-");
        e_cpus_ = new QLabel("-");
        u_cpus_ = new QLabel("-");

        status_layout->addRow("MSR raw", msr_raw_);
        status_layout->addRow("MSR PL1", msr_pl1_);
        status_layout->addRow("MSR PL2", msr_pl2_);

        status_layout->addRow("MMIO raw", mmio_raw_);
        status_layout->addRow("MMIO PL1", mmio_pl1_);
        status_layout->addRow("MMIO PL2", mmio_pl2_);
        status_layout->addRow("P cores", p_cpus_);
        status_layout->addRow("E cores", e_cpus_);
        status_layout->addRow("Unknown cores", u_cpus_);

        status_group_->setLayout(status_layout);
        root->addWidget(status_group_);

        auto *set_group = new QGroupBox("Set limits (watts)");
        auto *set_layout = new QVBoxLayout();
        auto *set_form = new QFormLayout();

        pl1_spin_ = new QDoubleSpinBox();
        pl1_spin_->setRange(1.0, 5000.0);
        pl1_spin_->setDecimals(2);
        pl1_spin_->setSingleStep(1.0);

        pl2_spin_ = new QDoubleSpinBox();
        pl2_spin_->setRange(1.0, 5000.0);
        pl2_spin_->setDecimals(2);
        pl2_spin_->setSingleStep(1.0);

        set_form->addRow("PL1 (W)", pl1_spin_);
        set_form->addRow("PL2 (W)", pl2_spin_);
        set_layout->addLayout(set_form);

        auto *set_buttons = new QHBoxLayout();
        set_msr_btn_ = new QPushButton("Set MSR");
        set_mmio_btn_ = new QPushButton("Set MMIO");
        set_both_btn_ = new QPushButton("Set Both");

        set_buttons->addWidget(set_msr_btn_);
        set_buttons->addWidget(set_mmio_btn_);
        set_buttons->addWidget(set_both_btn_);
        set_layout->addLayout(set_buttons);

        set_group->setLayout(set_layout);
        root->addWidget(set_group);

        auto *ratio_group = new QGroupBox("CPU ratio (multiplier)");
        auto *ratio_layout = new QVBoxLayout();
        auto *ratio_form = new QFormLayout();

        p_ratio_spin_ = new QSpinBox();
        p_ratio_spin_->setRange(1, 255);
        p_ratio_spin_->setSingleStep(1);

        e_ratio_spin_ = new QSpinBox();
        e_ratio_spin_->setRange(1, 255);
        e_ratio_spin_->setSingleStep(1);

        p_ratio_cur_ = new QLabel("-");
        e_ratio_cur_ = new QLabel("-");

        ratio_form->addRow("P-core ratio target (x)", p_ratio_spin_);
        ratio_form->addRow("P-core ratio current", p_ratio_cur_);
        ratio_form->addRow("E-core ratio target (x)", e_ratio_spin_);
        ratio_form->addRow("E-core ratio current", e_ratio_cur_);
        ratio_layout->addLayout(ratio_form);

        auto *ratio_buttons = new QHBoxLayout();
        set_p_ratio_btn_ = new QPushButton("Set P");
        set_e_ratio_btn_ = new QPushButton("Set E");
        set_pe_ratio_btn_ = new QPushButton("Set P+E");
        set_all_ratio_btn_ = new QPushButton("Set All");

        ratio_buttons->addWidget(set_p_ratio_btn_);
        ratio_buttons->addWidget(set_e_ratio_btn_);
        ratio_buttons->addWidget(set_pe_ratio_btn_);
        ratio_buttons->addWidget(set_all_ratio_btn_);
        ratio_layout->addLayout(ratio_buttons);

        ratio_group->setLayout(ratio_layout);
        root->addWidget(ratio_group);

        auto *uv_group = new QGroupBox("Voltage offset (mV)");
        auto *uv_layout = new QVBoxLayout();
        auto *uv_form = new QFormLayout();

        core_uv_spin_ = new QDoubleSpinBox();
        core_uv_spin_->setRange(-500.0, 500.0);
        core_uv_spin_->setDecimals(3);
        core_uv_spin_->setSingleStep(1.0);

        core_uv_cur_ = new QLabel("-");
        core_uv_raw_ = new QLabel("-");

        uv_form->addRow("Core offset target (mV)", core_uv_spin_);
        uv_form->addRow("Core offset current", core_uv_cur_);
        uv_form->addRow("Core offset raw", core_uv_raw_);
        uv_layout->addLayout(uv_form);

        core_uv_btn_ = new QPushButton("Set Core Offset");
        uv_layout->addWidget(core_uv_btn_);

        uv_group->setLayout(uv_layout);
        root->addWidget(uv_group);

        auto *sync_group = new QGroupBox("Sync + refresh");
        auto *sync_layout = new QHBoxLayout();

        refresh_btn_ = new QPushButton("Refresh");
        sync_msr_to_mmio_btn_ = new QPushButton("MSR -> MMIO");
        sync_mmio_to_msr_btn_ = new QPushButton("MMIO -> MSR");

        sync_layout->addWidget(refresh_btn_);
        sync_layout->addWidget(sync_msr_to_mmio_btn_);
        sync_layout->addWidget(sync_mmio_to_msr_btn_);
        sync_group->setLayout(sync_layout);
        root->addWidget(sync_group);

        log_ = new QPlainTextEdit();
        log_->setReadOnly(true);
        log_->setMaximumBlockCount(200);
        root->addWidget(log_);

        central->setLayout(root);
        setCentralWidget(central);

        connect(refresh_btn_, &QPushButton::clicked, this, &MainWindow::refresh);
        connect(set_msr_btn_, &QPushButton::clicked, this, [this]() { apply_limits(Target::Msr); });
        connect(set_mmio_btn_, &QPushButton::clicked, this, [this]() { apply_limits(Target::Mmio); });
        connect(set_both_btn_, &QPushButton::clicked, this, [this]() { apply_limits(Target::Both); });
        connect(set_p_ratio_btn_, &QPushButton::clicked, this, [this]() { apply_ratio(RatioTarget::P); });
        connect(set_e_ratio_btn_, &QPushButton::clicked, this, [this]() { apply_ratio(RatioTarget::E); });
        connect(set_pe_ratio_btn_, &QPushButton::clicked, this, [this]() { apply_ratio(RatioTarget::Both); });
        connect(set_all_ratio_btn_, &QPushButton::clicked, this, [this]() { apply_ratio(RatioTarget::All); });
        connect(core_uv_btn_, &QPushButton::clicked, this, &MainWindow::apply_core_uv);
        connect(sync_msr_to_mmio_btn_, &QPushButton::clicked, this, &MainWindow::sync_msr_to_mmio);
        connect(sync_mmio_to_msr_btn_, &QPushButton::clicked, this, &MainWindow::sync_mmio_to_msr);

        load_cpu_info();
        initialize_backend();
    }

private:
    enum class Target {
        Msr,
        Mmio,
        Both
    };

    enum class RatioTarget {
        P,
        E,
        Both,
        All
    };

    void initialize_backend() {
        QString err;
        if (!backend_.helper_available(&err)) {
            QMessageBox::critical(this, "Helper missing", err);
            set_controls_enabled(false);
            return;
        }
        set_controls_enabled(true);
        refresh();
    }

    void set_controls_enabled(bool enabled) {
        status_group_->setEnabled(enabled);
        set_msr_btn_->setEnabled(enabled);
        set_mmio_btn_->setEnabled(enabled);
        set_both_btn_->setEnabled(enabled);
        set_p_ratio_btn_->setEnabled(enabled);
        set_e_ratio_btn_->setEnabled(enabled);
        set_pe_ratio_btn_->setEnabled(enabled);
        set_all_ratio_btn_->setEnabled(enabled);
        refresh_btn_->setEnabled(enabled);
        sync_msr_to_mmio_btn_->setEnabled(enabled);
        sync_mmio_to_msr_btn_->setEnabled(enabled);
        pl1_spin_->setEnabled(enabled);
        pl2_spin_->setEnabled(enabled);
        p_ratio_spin_->setEnabled(enabled);
        e_ratio_spin_->setEnabled(enabled);
        core_uv_spin_->setEnabled(enabled);
        core_uv_btn_->setEnabled(enabled);
    }

    QLineEdit *make_readonly_line() {
        auto *line = new QLineEdit();
        line->setReadOnly(true);
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        line->setFont(mono);
        return line;
    }

    void log_message(const QString &msg) {
        QString stamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
        log_->appendPlainText(stamp + "  " + msg);
    }

    void load_cpu_info() {
        CpuInfo info = read_cpu_info();
        cpu_vendor_->setText(info.vendor.isEmpty() ? "-" : info.vendor);
        cpu_model_name_->setText(info.model_name.isEmpty() ? "-" : info.model_name);

        QString fam_model_step;
        if (!info.family.isEmpty() || !info.model.isEmpty() || !info.stepping.isEmpty()) {
            fam_model_step = QString("family %1, model %2, stepping %3")
                                 .arg(info.family.isEmpty() ? "?" : info.family)
                                 .arg(info.model.isEmpty() ? "?" : info.model)
                                 .arg(info.stepping.isEmpty() ? "?" : info.stepping);
        }
        cpu_family_model_->setText(fam_model_step.isEmpty() ? "-" : fam_model_step);

        cpu_microcode_->setText(info.microcode.isEmpty() ? "-" : info.microcode);
        cpu_cache_->setText(info.cache_size.isEmpty() ? "-" : info.cache_size);

        cpu_logical_->setText(info.logical_cpus > 0 ? QString::number(info.logical_cpus) : "-");
        cpu_physical_->setText(info.physical_cores > 0 ? QString::number(info.physical_cores) : "-");
        cpu_packages_->setText(info.packages > 0 ? QString::number(info.packages) : "-");

        if (info.min_mhz > 0.0 || info.max_mhz > 0.0) {
            if (info.min_mhz > 0.0 && info.max_mhz > 0.0) {
                cpu_freq_->setText(QString("%1 / %2")
                                       .arg(info.min_mhz, 0, 'f', 0)
                                       .arg(info.max_mhz, 0, 'f', 0));
            } else if (info.max_mhz > 0.0) {
                cpu_freq_->setText(QString("max %1").arg(info.max_mhz, 0, 'f', 0));
            } else {
                cpu_freq_->setText(QString("min %1").arg(info.min_mhz, 0, 'f', 0));
            }
        } else {
            cpu_freq_->setText("-");
        }
    }

    static int count_list(const QString &list) {
        if (list.isEmpty()) {
            return 0;
        }
        QStringList parts = list.split(',', Qt::SkipEmptyParts);
        return parts.size();
    }

    bool update_units(const ReadState &state) {
        if (state.unit_watts <= 0.0) {
            return false;
        }
        power_unit_ = state.power_unit;
        unit_watts_ = state.unit_watts;
        unit_label_->setText(QString("2^-%1 W = %2 W")
                                 .arg(power_unit_)
                                 .arg(unit_watts_, 0, 'f', 6));
        return true;
    }

    void refresh() {
        QString err;
        ReadState state;
        if (!backend_.read_state(state, &err)) {
            show_error("Read failed", err);
            return;
        }

        if (!update_units(state)) {
            show_error("Invalid unit", "Power unit is unknown or zero.");
            return;
        }

        update_msr(state.msr);
        update_mmio(state.mmio);
        update_core_info(state);
        maybe_init_limits(state);
    }

    void update_msr(std::uint64_t val) {
        msr_raw_->setText(hex64(val));
        std::uint16_t pl1 = static_cast<std::uint16_t>(val & 0x7FFFu);
        std::uint16_t pl2 = static_cast<std::uint16_t>((val >> 32) & 0x7FFFu);
        msr_pl1_->setText(units_to_text(pl1, unit_watts_));
        msr_pl2_->setText(units_to_text(pl2, unit_watts_));
    }

    void update_mmio(std::uint64_t val) {
        mmio_raw_->setText(hex64(val));
        std::uint16_t pl1 = static_cast<std::uint16_t>(val & 0x7FFFu);
        std::uint16_t pl2 = static_cast<std::uint16_t>((val >> 32) & 0x7FFFu);
        mmio_pl1_->setText(units_to_text(pl1, unit_watts_));
        mmio_pl2_->setText(units_to_text(pl2, unit_watts_));
    }

    void update_core_info(const ReadState &state) {
        p_cpus_->setText(state.p_cpus.isEmpty() ? "-" : state.p_cpus);
        e_cpus_->setText(state.e_cpus.isEmpty() ? "-" : state.e_cpus);
        u_cpus_->setText(state.u_cpus.isEmpty() ? "-" : state.u_cpus);

        int p_count = count_list(state.p_cpus);
        int e_count = count_list(state.e_cpus);
        cpu_p_count_->setText(p_count > 0 ? QString::number(p_count) : "-");
        cpu_e_count_->setText(e_count > 0 ? QString::number(e_count) : "-");

        bool has_p = !state.p_cpus.isEmpty();
        bool has_e = !state.e_cpus.isEmpty();
        bool has_any = has_p || has_e || !state.u_cpus.isEmpty();

        p_ratio_spin_->setEnabled(has_p);
        set_p_ratio_btn_->setEnabled(has_p);
        e_ratio_spin_->setEnabled(has_e);
        set_e_ratio_btn_->setEnabled(has_e);
        set_pe_ratio_btn_->setEnabled(has_p || has_e);
        set_all_ratio_btn_->setEnabled(has_any);

        if (state.p_ratio_valid && has_p) {
            p_ratio_spin_->setValue(state.p_ratio);
        }
        if (state.e_ratio_valid && has_e) {
            e_ratio_spin_->setValue(state.e_ratio);
        }

        if (state.p_ratio_cur_valid && has_p) {
            p_ratio_cur_->setText(QString("x%1").arg(state.p_ratio_cur));
        } else {
            p_ratio_cur_->setText("-");
        }
        if (state.e_ratio_cur_valid && has_e) {
            e_ratio_cur_->setText(QString("x%1").arg(state.e_ratio_cur));
        } else {
            e_ratio_cur_->setText("-");
        }

        cpu_p_mhz_->setText(format_mhz_stats(parse_cpu_list(state.p_cpus)));
        cpu_e_mhz_->setText(format_mhz_stats(parse_cpu_list(state.e_cpus)));

        if (state.core_uv_valid) {
            core_uv_spin_->setValue(state.core_uv_mv);
            core_uv_cur_->setText(QString("%1 mV").arg(state.core_uv_mv, 0, 'f', 3));
        } else {
            core_uv_cur_->setText("-");
        }
        core_uv_raw_->setText(state.core_uv_raw.isEmpty() ? "-" : state.core_uv_raw);
    }

    void maybe_init_limits(const ReadState &state) {
        if (did_init_limits_) {
            return;
        }
        std::uint64_t base = state.msr != 0 ? state.msr : state.mmio;
        std::uint16_t pl1 = static_cast<std::uint16_t>(base & 0x7FFFu);
        std::uint16_t pl2 = static_cast<std::uint16_t>((base >> 32) & 0x7FFFu);
        if (pl1 == 0 || pl2 == 0 || unit_watts_ <= 0.0) {
            return;
        }
        double pl1_w = static_cast<double>(pl1) * unit_watts_;
        double pl2_w = static_cast<double>(pl2) * unit_watts_;
        pl1_spin_->setValue(pl1_w);
        pl2_spin_->setValue(pl2_w);
        did_init_limits_ = true;
    }

    bool build_units(double unit_watts, std::uint16_t &pl1_units, std::uint16_t &pl2_units) {
        if (unit_watts <= 0.0) {
            show_error("Invalid unit", "Power unit is unknown or zero.");
            return false;
        }

        double pl1_w = pl1_spin_->value();
        double pl2_w = pl2_spin_->value();

        std::uint64_t pl1_calc = static_cast<std::uint64_t>(std::llround(pl1_w / unit_watts));
        std::uint64_t pl2_calc = static_cast<std::uint64_t>(std::llround(pl2_w / unit_watts));

        if (pl1_calc == 0 || pl2_calc == 0 || pl1_calc > 0x7FFFu || pl2_calc > 0x7FFFu) {
            show_error("Invalid values", "Converted units out of range.");
            return false;
        }

        pl1_units = static_cast<std::uint16_t>(pl1_calc);
        pl2_units = static_cast<std::uint16_t>(pl2_calc);
        return true;
    }

    void apply_limits(Target target) {
        QString err;
        ReadState state;
        if (!backend_.read_state(state, &err)) {
            show_error("Read failed", err);
            return;
        }
        if (!update_units(state)) {
            show_error("Invalid unit", "Power unit is unknown or zero.");
            return;
        }

        std::uint16_t pl1_units = 0;
        std::uint16_t pl2_units = 0;
        if (!build_units(state.unit_watts, pl1_units, pl2_units)) {
            return;
        }

        if (target == Target::Msr || target == Target::Both) {
            std::uint64_t next = apply_pl_units(state.msr, pl1_units, pl2_units);
            if (!confirm_action("Write MSR?",
                                QString("MSR (0x%1) new value: %2")
                                    .arg(kMsrPkgPowerLimit, 0, 16)
                                    .arg(hex64(next)))) {
                return;
            }
            if (!backend_.write_msr(next, &err)) {
                show_error("Write MSR failed", err);
                return;
            }
            log_message(QString("Wrote MSR %1").arg(hex64(next)));
        }

        if (target == Target::Mmio || target == Target::Both) {
            std::uint64_t next = apply_pl_units(state.mmio, pl1_units, pl2_units);
            if (!confirm_action("Write MMIO?",
                                QString("MMIO (0x%1) new value: %2")
                                    .arg(kMchbarPlOffset, 0, 16)
                                    .arg(hex64(next)))) {
                return;
            }
            if (!backend_.write_mmio(next, &err)) {
                show_error("Write MMIO failed", err);
                return;
            }
            log_message(QString("Wrote MMIO %1").arg(hex64(next)));
        }

        refresh();
    }

    void apply_ratio(RatioTarget target) {
        QString err;
        int p_ratio = p_ratio_spin_->value();
        int e_ratio = e_ratio_spin_->value();

        if (target == RatioTarget::P) {
            if (!confirm_action("Set P-core ratio?",
                                QString("P-core ratio target: x%1").arg(p_ratio))) {
                return;
            }
            if (!backend_.set_p_ratio(p_ratio, &err)) {
                show_error("Set P-core ratio failed", err);
                return;
            }
            log_message(QString("Set P-core ratio x%1").arg(p_ratio));
        } else if (target == RatioTarget::E) {
            if (!confirm_action("Set E-core ratio?",
                                QString("E-core ratio target: x%1").arg(e_ratio))) {
                return;
            }
            if (!backend_.set_e_ratio(e_ratio, &err)) {
                show_error("Set E-core ratio failed", err);
                return;
            }
            log_message(QString("Set E-core ratio x%1").arg(e_ratio));
        } else if (target == RatioTarget::Both) {
            if (!confirm_action("Set P/E ratio?",
                                QString("P-core ratio x%1, E-core ratio x%2")
                                    .arg(p_ratio)
                                    .arg(e_ratio))) {
                return;
            }
            if (!backend_.set_pe_ratio(p_ratio, e_ratio, &err)) {
                show_error("Set P/E ratio failed", err);
                return;
            }
            log_message(QString("Set P/E ratio x%1 / x%2").arg(p_ratio).arg(e_ratio));
        } else {
            int ratio = p_ratio;
            if (!confirm_action("Set all core ratios?",
                                QString("All cores ratio target: x%1").arg(ratio))) {
                return;
            }
            if (!backend_.set_all_ratio(ratio, &err)) {
                show_error("Set all ratios failed", err);
                return;
            }
            log_message(QString("Set all core ratios x%1").arg(ratio));
        }

        refresh();
    }

    void apply_core_uv() {
        QString err;
        double mv = core_uv_spin_->value();
        if (!confirm_action("Set core voltage offset?",
                            QString("Core offset target: %1 mV").arg(mv, 0, 'f', 3))) {
            return;
        }
        if (!backend_.set_core_uv(mv, &err)) {
            show_error("Set core offset failed", err);
            return;
        }
        log_message(QString("Set core offset %1 mV").arg(mv, 0, 'f', 3));
        refresh();
    }

    void sync_msr_to_mmio() {
        QString err;
        ReadState state;
        if (!backend_.read_state(state, &err)) {
            show_error("Read failed", err);
            return;
        }

        if (!confirm_action("Sync MSR -> MMIO?",
                            QString("MMIO (0x%1) will be set to %2")
                                .arg(kMchbarPlOffset, 0, 16)
                                .arg(hex64(state.msr)))) {
            return;
        }
        if (!backend_.write_mmio(state.msr, &err)) {
            show_error("Write MMIO failed", err);
            return;
        }
        log_message(QString("Synced MSR -> MMIO (%1)").arg(hex64(state.msr)));
        refresh();
    }

    void sync_mmio_to_msr() {
        QString err;
        ReadState state;
        if (!backend_.read_state(state, &err)) {
            show_error("Read failed", err);
            return;
        }

        if (!confirm_action("Sync MMIO -> MSR?",
                            QString("MSR (0x%1) will be set to %2")
                                .arg(kMsrPkgPowerLimit, 0, 16)
                                .arg(hex64(state.mmio)))) {
            return;
        }
        if (!backend_.write_msr(state.mmio, &err)) {
            show_error("Write MSR failed", err);
            return;
        }
        log_message(QString("Synced MMIO -> MSR (%1)").arg(hex64(state.mmio)));
        refresh();
    }

    bool confirm_action(const QString &title, const QString &detail) {
        QMessageBox box(this);
        box.setWindowTitle(title);
        box.setText(title);
        box.setInformativeText(detail);
        box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        box.setDefaultButton(QMessageBox::No);
        return box.exec() == QMessageBox::Yes;
    }

    void show_error(const QString &title, const QString &detail) {
        QMessageBox::critical(this, title, detail);
        log_message(title + ": " + detail);
    }

    HelperBackend backend_;
    int power_unit_ = 0;
    double unit_watts_ = 0.0;
    bool did_init_limits_ = false;

    QGroupBox *cpu_group_ = nullptr;
    QLabel *cpu_vendor_ = nullptr;
    QLabel *cpu_model_name_ = nullptr;
    QLabel *cpu_family_model_ = nullptr;
    QLabel *cpu_microcode_ = nullptr;
    QLabel *cpu_cache_ = nullptr;
    QLabel *cpu_logical_ = nullptr;
    QLabel *cpu_physical_ = nullptr;
    QLabel *cpu_packages_ = nullptr;
    QLabel *cpu_freq_ = nullptr;
    QLabel *cpu_p_count_ = nullptr;
    QLabel *cpu_e_count_ = nullptr;
    QLabel *cpu_p_mhz_ = nullptr;
    QLabel *cpu_e_mhz_ = nullptr;

    QGroupBox *status_group_ = nullptr;
    QLabel *unit_label_ = nullptr;
    QLineEdit *msr_raw_ = nullptr;
    QLineEdit *mmio_raw_ = nullptr;
    QLabel *msr_pl1_ = nullptr;
    QLabel *msr_pl2_ = nullptr;
    QLabel *mmio_pl1_ = nullptr;
    QLabel *mmio_pl2_ = nullptr;
    QLabel *p_cpus_ = nullptr;
    QLabel *e_cpus_ = nullptr;
    QLabel *u_cpus_ = nullptr;

    QDoubleSpinBox *pl1_spin_ = nullptr;
    QDoubleSpinBox *pl2_spin_ = nullptr;
    QSpinBox *p_ratio_spin_ = nullptr;
    QSpinBox *e_ratio_spin_ = nullptr;
    QLabel *p_ratio_cur_ = nullptr;
    QLabel *e_ratio_cur_ = nullptr;
    QDoubleSpinBox *core_uv_spin_ = nullptr;
    QLabel *core_uv_cur_ = nullptr;
    QLabel *core_uv_raw_ = nullptr;

    QPushButton *refresh_btn_ = nullptr;
    QPushButton *set_msr_btn_ = nullptr;
    QPushButton *set_mmio_btn_ = nullptr;
    QPushButton *set_both_btn_ = nullptr;
    QPushButton *set_p_ratio_btn_ = nullptr;
    QPushButton *set_e_ratio_btn_ = nullptr;
    QPushButton *set_pe_ratio_btn_ = nullptr;
    QPushButton *set_all_ratio_btn_ = nullptr;
    QPushButton *core_uv_btn_ = nullptr;
    QPushButton *sync_msr_to_mmio_btn_ = nullptr;
    QPushButton *sync_mmio_to_msr_btn_ = nullptr;

    QPlainTextEdit *log_ = nullptr;
};

#include "main.moc"

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    MainWindow window;
    window.resize(720, 600);
    window.show();
    return app.exec();
}
