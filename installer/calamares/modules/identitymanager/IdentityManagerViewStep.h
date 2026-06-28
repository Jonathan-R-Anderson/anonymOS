/* EpinAnonymOS — Identity Manager Calamares view module (roadmap/INSTALLER.md Phase 6).
 *
 * Presents an Administrator account + toggleable Identity profiles. On leaving the page it
 * writes the selected identities (as JSON) into Calamares GlobalStorage under "epinIdentities";
 * the epinconfig job (Phase 7) folds that into the declarative install.json, and first boot
 * materialises each as a Domain/identity OBJECT (core/domain.d). Nothing is created here.
 *
 * NOTE: compiles only once deps/qt-stack (static Qt6) + Calamares are built (§D1/§D3).
 */
#ifndef IDENTITYMANAGERVIEWSTEP_H
#define IDENTITYMANAGERVIEWSTEP_H

#include <QObject>
#include <QVariantMap>
#include <utils/PluginFactory.h>
#include <viewpages/ViewStep.h>

class QWidget;

class IdentityManagerViewStep : public Calamares::ViewStep
{
    Q_OBJECT
public:
    explicit IdentityManagerViewStep( QObject* parent = nullptr );
    ~IdentityManagerViewStep() override;

    QString prettyName() const override;
    QWidget* widget() override;

    bool isNextEnabled() const override;
    bool isBackEnabled() const override;
    bool isAtBeginning() const override;
    bool isAtEnd() const override;

    Calamares::JobList jobs() const override;
    void onActivate() override;
    void onLeave() override;                 // writes "epinIdentities" into GlobalStorage

    void setConfigurationMap( const QVariantMap& configurationMap ) override;

private:
    QWidget* m_widget = nullptr;
    QVariantList m_profiles;                 // from identitymanager.conf
};

CALAMARES_PLUGIN_FACTORY_DECLARATION( IdentityManagerViewStepFactory )

#endif
