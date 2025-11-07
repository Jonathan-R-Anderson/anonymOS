module cmd_false;

import core.stdc.stdlib : exit;

/// Do nothing and return a failure status.
void falseMain(string[] args)
{
    exit(1);
}
