from alembic import context

from backend.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("gateway migrations require the application-managed connection")
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        transactional_ddl=True,
    )
    with context.begin_transaction():
        context.run_migrations()


run_migrations()
