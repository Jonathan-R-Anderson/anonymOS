/* EpinAnonymOS — Identity Manager Calamares view module (roadmap/INSTALLER.md Phase 6).
 * See IdentityManagerViewStep.h. Skeleton: a checkbox list of Identity profiles whose
 * selection is published to GlobalStorage["epinIdentities"] for the epinconfig job.
 */
#include "IdentityManagerViewStep.h"

#include <Calamares/GlobalStorage.h>
#include <Calamares/JobQueue.h>

#include <QCheckBox>
#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

CALAMARES_PLUGIN_FACTORY_DEFINITION( IdentityManagerViewStepFactory, registerPlugin<IdentityManagerViewStep>(); )

IdentityManagerViewStep::IdentityManagerViewStep( QObject* parent )
    : Calamares::ViewStep( parent )
{
}

IdentityManagerViewStep::~IdentityManagerViewStep() = default;

QString IdentityManagerViewStep::prettyName() const { return tr( "Identities" ); }

QWidget* IdentityManagerViewStep::widget()
{
    if ( m_widget )
        return m_widget;

    m_widget = new QWidget;
    auto* layout = new QVBoxLayout( m_widget );
    layout->addWidget( new QLabel( tr( "Choose the Identity profiles to provision. Each becomes "
                                       "an isolated, capability-gated domain object." ) ) );
    for ( const auto& p : m_profiles )
    {
        const QVariantMap m = p.toMap();
        auto* cb = new QCheckBox( m.value( "name" ).toString(), m_widget );
        cb->setChecked( m.value( "default" ).toBool() );
        cb->setProperty( "epinProfileId", m.value( "id" ) );
        cb->setToolTip( m.value( "description" ).toString() );
        layout->addWidget( cb );
    }
    layout->addStretch();
    return m_widget;
}

void IdentityManagerViewStep::onLeave()
{
    QVariantList chosen;
    if ( m_widget )
    {
        const auto boxes = m_widget->findChildren< QCheckBox* >();
        for ( auto* cb : boxes )
            if ( cb->isChecked() )
                chosen.append( cb->property( "epinProfileId" ) );
    }
    Calamares::JobQueue::instance()->globalStorage()->insert( "epinIdentities", chosen );
}

void IdentityManagerViewStep::setConfigurationMap( const QVariantMap& cfg )
{
    m_profiles = cfg.value( "profiles" ).toList();
}

bool IdentityManagerViewStep::isNextEnabled() const { return true; }
bool IdentityManagerViewStep::isBackEnabled() const { return true; }
bool IdentityManagerViewStep::isAtBeginning() const { return true; }
bool IdentityManagerViewStep::isAtEnd() const { return true; }
Calamares::JobList IdentityManagerViewStep::jobs() const { return {}; }
void IdentityManagerViewStep::onActivate() {}

#include "IdentityManagerViewStep.moc"
