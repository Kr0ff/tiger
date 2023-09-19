#pragma once

#define FALSE 0
#define TRUE 1

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( FALSE )
#else
#define DEBUG_PRINT(...) do{ } while ( FALSE )
#endif