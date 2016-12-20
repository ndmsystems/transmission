/*
 * This file Copyright (C) 2009-2016 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 * $Id: transmission.c 14241 2016-12-20 23:25:35Z $
 */

#include "transmission.h"
#include "crypto.h"

bool
tr_libraryInit (void)
{
  return tr_cryptoInit ();
}

void
tr_libraryFree (void)
{
  tr_cryptoFree ();
}
