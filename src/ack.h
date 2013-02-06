/***************************************************************************
 *  Original Diku Mud copyright (C) 1990, 1991 by Sebastian Hammer,        *
 *  Michael Seifert, Hans Henrik St{rfeldt, Tom Madsen, and Katja Nyboe.   *
 *                                                                         *
 *  Merc Diku Mud improvments copyright (C) 1992, 1993 by Michael          *
 *  Chastain, Michael Quan, and Mitchell Tse.                              *
 *                                                                         *
 *  Ack 2.2 improvements copyright (C) 1994 by Stephen Dooley              *
 *                                                                         *
 *  In order to use any part of this Merc Diku Mud, you must comply with   *
 *  both the original Diku license in 'license.doc' as well the Merc       *
 *  license in 'license.txt'.  In particular, you may not remove either of *
 *  these copyright notices.                                               *
 *                                                                         *
 *       _/          _/_/_/     _/    _/     _/    ACK! MUD is modified    *
 *      _/_/        _/          _/  _/       _/    Merc2.0/2.1/2.2 code    *
 *     _/  _/      _/           _/_/         _/    (c)Stephen Zepp 1998    *
 *    _/_/_/_/      _/          _/  _/             Version #: 4.3          *
 *   _/      _/      _/_/_/     _/    _/     _/                            *
 *                                                                         *
 *                                                                         *
 *  Much time and thought has gone into this software and you are          *
 *  benefitting.  We hope that you share your changes too.  What goes      *
 *  around, comes around.                                                  *
 ***************************************************************************/

#define DEC_ACK_H 1

#if defined(macintosh)
#include <types.h>
#else
#include <sys/types.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
/* For forks etc. */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

/*
 * Accommodate old non-Ansi compilers.
 */
#if defined(TRADITIONAL)
#define const
#define args( list )                    ( )
#define DECLARE_DO_FUN( fun )           void fun( )
#define DECLARE_SPEC_FUN( fun )         bool fun( )
#define DECLARE_OBJ_FUN( fun )      void fun( )
#define DECLARE_ACT_FUN( fun )      void fun( )
#else
#define args( list )                    list
#define DECLARE_DO_FUN( fun )           DO_FUN    fun
#define DECLARE_SPEC_FUN( fun )         SPEC_FUN  fun
#define DECLARE_OBJ_FUN( fun )          OBJ_FUN   fun
#define DECLARE_ACT_FUN( fun )          ACT_FUN   fun
#endif

/*
 * Short scalar types.
 * Diavolo reports AIX compiler has bugs with short types.
 */
#if     !defined(NOWHERE)
#define NOWHERE -1
#endif

#if     !defined(FALSE)
#define FALSE    0
#endif

#if     !defined(TRUE)
#define TRUE     1
#endif

#if     defined(_AIX)
#if     !defined(const)
#define const
#endif
typedef int                             sh_int;
typedef int                             bool;
#define unix
#else
#if !defined(sh_int)
typedef short    int                    sh_int;
#endif
#if !defined(bool)
typedef unsigned char                   bool;
#endif
#endif
typedef int                             long_int;
typedef unsigned long int       bitset;

/*
 * OS-dependent declarations.
 * These are all very standard library functions,
 *   but some systems have incomplete or non-ansi header files.
 */
#if     defined(_AIX)
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

#if     defined(apollo)
int     atoi            args( ( const char *string ) );
void *  calloc          args( ( unsigned nelem, size_t size ) );
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

#if     defined(hpux)
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

#if     defined(linux)
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

#if     defined(macintosh)
#define NOCRYPT
#if     defined(unix)
#undef  unix
#endif
#endif

#if     defined(MIPS_OS)
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

#if     defined(MSDOS)
#define NOCRYPT
#if     defined(unix)
#undef  unix
#endif
#endif

#if     defined(NeXT)
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

#if     defined(sequent)
char *  crypt           args( ( const char *key, const char *salt ) );
int     fclose          args( ( FILE *stream ) );
int     fprintf         args( ( FILE *stream, const char *format, ... ) );
int     fread           args( ( void *ptr, int size, int n, FILE *stream ) );
int     fseek           args( ( FILE *stream, long offset, int ptrname ) );
void    perror          args( ( const char *s ) );
int     ungetc          args( ( int c, FILE *stream ) );
#endif

#if     defined(sun)
char *  crypt           args( ( const char *key, const char *salt ) );
int     fclose          args( ( FILE *stream ) );
int     fprintf         args( ( FILE *stream, const char *format, ... ) );
#if defined(SYSV)
size_t  fread       args( ( void *ptr, size_t size, size_t n, FILE *stream ) );
#else
int     fread           args( ( void *ptr, int size, int n, FILE *stream ) );
#endif
int     fseek           args( ( FILE *stream, long offset, int ptrname ) );
void    perror          args( ( const char *s ) );
int     ungetc          args( ( int c, FILE *stream ) );
#endif

#if     defined(ultrix)
char *  crypt           args( ( const char *key, const char *salt ) );
#endif

/*
 * The crypt(3) function is not available on some operating systems.
 * In particular, the U.S. Government prohibits its export from the
 *   United States to foreign countries.
 * Turn on NOCRYPT to keep passwords in plain text.
 */
#if     defined(NOCRYPT)
#define crypt(s1, s2)   (s1)
#endif

typedef struct  relevel_data            RELEVEL_DATA;
typedef struct  area_data               AREA_DATA;
typedef struct  ban_data                BAN_DATA;
typedef struct  char_data               CHAR_DATA;
typedef struct  changes_data            CHANGE_DATA;
typedef struct  descriptor_data         DESCRIPTOR_DATA;
typedef struct  extra_descr_data        EXTRA_DESCR_DATA;
typedef struct  help_data               HELP_DATA;
typedef struct  kill_data               KILL_DATA;
typedef struct  log_data                LOG_DATA;
typedef struct  obj_data                OBJ_DATA;
typedef struct  obj_index_data          OBJ_INDEX_DATA;
typedef struct  pc_data                 PC_DATA;
typedef struct  room_index_data         ROOM_INDEX_DATA;
typedef struct  time_info_data          TIME_INFO_DATA;
typedef struct  weather_data            WEATHER_DATA;
typedef struct  disabled_data           DISABLED_DATA;      /* Disabling of commands - Wyn */
typedef struct  build_data_list         BUILD_DATA_LIST;    /* Online Building */
typedef struct  building_data           BUILDING_DATA;
typedef struct  vehicle_data            VEHICLE_DATA;
typedef struct  trigger_data              TRIGGER_DATA;
typedef struct  load_data       LOAD_DATA;

typedef struct bomb_data               BOMB_DATA;
typedef struct pager_data              PAGER_DATA;
typedef struct queue_data              QUEUE_DATA;
typedef struct message_data            MESSAGE_DATA;
typedef struct board_data              BOARD_DATA;
typedef struct  control_data              CONTROL_DATA;
typedef struct  influence_data            INFLUENCE_DATA;
typedef struct  interact_data             INTERACT_DATA;
typedef struct  influence_list            INFLUENCE_LIST;
typedef struct  control_list              CONTROL_LIST;
typedef struct  queued_interact_list       QUEUED_INTERACT_LIST;
typedef struct  dl_list                  DL_LIST;
typedef struct  brand_data               BRAND_DATA;
typedef struct str_array               STR_ARRAY;
typedef struct sysdata_type           SYS_DATA_TYPE;
typedef struct buf_data_struct BUF_DATA_STRUCT;
typedef struct hash_entry_tp  HASH_ENTRY;

/*
 * Function types.
 */
typedef void DO_FUN     args( ( CHAR_DATA *ch, char *argument ) );
typedef bool SPEC_FUN   args( ( CHAR_DATA *ch ) );
typedef void OBJ_FUN    args( ( OBJ_DATA *obj, CHAR_DATA *keeper ) );
typedef void ACT_FUN    args( ( CHAR_DATA *ch, int level ) );

/*
 * Extended bitvector type
 */
typedef struct  bitvector_data      XBV;

//#define MAX_BUILDING			123
#define BUILDING_REVISION       0
#define MAX_POSSIBLE_BUILDING       155
#define BUILDING_LIMIT          (sysdata.killfest ? 30 : ((MAX_BUILDING / 4) * 3))

#define MAX_BUILDING_TYPES      7
#define BUILDING_CORE           0
#define BUILDING_SUPERWEAPON        1
#define BUILDING_DEFENSE        2
#define BUILDING_OFFENSE        3
#define BUILDING_LAB            4
#define BUILDING_RESOURCES      5
#define BUILDING_OTHER          6

#define BUILDING_EMPTY          0
#define BUILDING_HQ         1
#define BUILDING_ARMORY         2
#define BUILDING_S_TURRET       3
#define BUILDING_QUARRY         4
#define BUILDING_MINE           5
#define BUILDING_STORAGE        6
#define BUILDING_LUMBERYARD     7
#define BUILDING_TANNERY        8
#define BUILDING_TURRET         9
#define BUILDING_L_TURRET       10
#define BUILDING_WATCHTOWER     11
#define BUILDING_WAR_CANNON     12
#define BUILDING_WEAPONS_LAB        13
#define BUILDING_BIO_LAB        14
#define BUILDING_CHEMICAL_FACTORY   15
#define BUILDING_TECH_LAB       16
#define BUILDING_WARP           17
#define BUILDING_EXPLOSIVES_SUPPLIER    18
#define BUILDING_MEDICAL_CENTER     19
#define BUILDING_GARAGE         20
#define BUILDING_RADAR          21
#define BUILDING_JAMMER         22
#define BUILDING_WAREHOUSE      23
#define BUILDING_BOT_FACTORY        24
#define BUILDING_FORGE          25
#define BUILDING_SCUD_LAUNCHER      26
#define BUILDING_ARMORER        27
#define BUILDING_NUKE_LAUNCHER      28
#define BUILDING_AIRFIELD       29
#define BUILDING_WARP_TOWER     30
#define BUILDING_ROCK_TOWER     31
#define BUILDING_FIRE_TURRET        32
#define BUILDING_COOKIE_FACTORY     33
#define BUILDING_ACID_TURRET        34
#define BUILDING_GOVERNMENT_HALL    35
#define BUILDING_BAR            36
#define BUILDING_BANK           37
#define BUILDING_CLUB           38
#define BUILDING_FLAMESPITTER       39
#define BUILDING_LASER_TOWER        40
#define BUILDING_LASER_WORKSHOP     41
#define BUILDING_SOLAR_FACILITY     42
#define BUILDING_IMPLANT_RESEARCH   43
#define BUILDING_ATOM_BOMBER        44
#define BUILDING_HUNTING_LODGE      45
#define BUILDING_DOOMSDAY_DEVICE    46
#define BUILDING_MINING_LAB     47
#define BUILDING_IMPROVED_MINE      48
#define BUILDING_REFINERY       49
#define BUILDING_MARKETPLACE        50
#define BUILDING_MAGNET_TOWER       51
#define BUILDING_SHIELD_GENERATOR   52
#define BUILDING_TRAFFIC_JAMMER     53
#define BUILDING_CLONING_FACILITY   54
#define BUILDING_PROCESSING_PLANT   55
#define BUILDING_WATER_PUMP     56
#define BUILDING_HYDRO_PUMP     57
#define BUILDING_TUNNEL         58
#define BUILDING_SURFACE_JOLTER     59
#define BUILDING_COMPUTER_LAB       60
#define BUILDING_BATTERY        61
#define BUILDING_CHIP_FACTORY       62
#define BUILDING_WEB_RESEARCH       63
#define BUILDING_TRANSMISSION_TOWER 64
#define BUILDING_ONLINE_MARKET      65
#define BUILDING_BOOM           66
#define BUILDING_HACKERS_HIDEOUT    67
#define BUILDING_SNIPER_TOWER       68
#define BUILDING_TRAP           69
#define BUILDING_HACKPORT       70
#define BUILDING_UNDERGROUND_TURRET 71
#define BUILDING_ZAP            72
#define BUILDING_DIRT_TURRET        73
#define BUILDING_T_TURRET       74
#define BUILDING_SNOW_DIGGER        75
#define BUILDING_DEFENSE_LAB        76
#define BUILDING_STUNGUN        77
#define BUILDING_POISON_TURRET      78
#define BUILDING_SECURE_WAREHOUSE   79
#define BUILDING_CREEPER_COLONY     80
#define BUILDING_LAVA_THROWER       81
#define BUILDING_ALIEN_LAB      82
#define BUILDING_ENCRYPTION_POD     83
#define BUILDING_ARMOR_FACTORY      84
#define BUILDING_GUNNER         85
#define BUILDING_STATUE_DEMISE      86
#define BUILDING_LASER_BATTERY      87
#define BUILDING_COMM_LAB       88
#define BUILDING_SPY_TRAINING       89
#define BUILDING_TRANSMITTER        90
#define BUILDING_SPY_QUARTERS       91
#define BUILDING_SPY_SATELLITE      92
#define BUILDING_PROJECTOR      93
#define BUILDING_WAVE_GENERATOR     94
#define BUILDING_PSYCHIC_LAB        95
#define BUILDING_PSYCHOSTER     96
#define BUILDING_MIND_TOWER     97
#define BUILDING_PSYCHIC_TORMENTOR  98
#define BUILDING_PSYCHIC_SHIELD     99
#define BUILDING_COOLER         100
#define BUILDING_PARADROP       101
#define BUILDING_PROGRAMMER_SHACK   102
#define BUILDING_GATHERER       103
#define BUILDING_PSYCHIC_RADAR      104
#define BUILDING_DUMMY          105
#define BUILDING_PARTICLE_EMITTER   106
#define BUILDING_SONIC_BLASTER      107
#define BUILDING_EMP_RESEARCH       108
#define BUILDING_EARTHQUAKER        109
#define BUILDING_PSYCHIC_EYES       110
#define BUILDING_PSYCHIC_AMPLIFIER  111
#define BUILDING_SPACE_CENTER       112
#define BUILDING_TELEPORTER     113
#define BUILDING_MISSILE_DEFENSE    114
#define BUILDING_FLASH_TOWER        115
#define BUILDING_STATUE_SPELGURU    116
#define BUILDING_STATUE_CYLIS       117
#define BUILDING_ENGINEER_HOME      118
#define BUILDING_WEATHER_MACHINE    119
#define BUILDING_BLACKOUT       120
#define BUILDING_PORTAL         121
#define BUILDING_SHOCKWAVE      122
#define BUILDING_TRACTOR_BEAM       123
#define BUILDING_MOTHERSHIP_COMM    124
#define BUILDING_MOTHERSHIP_RESEARCH    125
#define BUILDING_INFRARED_TOWER     126
#define BUILDING_SPECIES_RESEARCH   127
#define BUILDING_ORGANIC_CHAMBER    128
#define BUILDING_ALIEN_PROBE        129
#define BUILDING_INTERGALACTIC_PUB  130
#define BUILDING_STATUE_WULFSTON    131
#define BUILDING_STATUE_SERYX       132
#define BUILDING_VIRUS_ANALYZER     133
#define BUILDING_ACIDBLASTER        134
#define BUILDING_ROCKETCANNON   135


#define DEC_CONFIG_H        1

/*
 *  Your mud info here :) Zen
 */

#define mudnamecolor                "@@aAssault: High Tech War @@fREBORN@@N"
#define mudnamenocolor              "Assault: High Tech War"
#define UPGRADE_REVISION            16
#define WEBSITE                     "http://orcs.biz/assault"
#define admin                       "Alvin"
#define admin_email                 "alvintheliche@gmail.com"
/*
 * String and memory management parameters.
 */
#define MAX_KEY_HASH                2048
#define MAX_STRING_LENGTH           8192
#define MSL                         MAX_STRING_LENGTH
#define MAX_INPUT_LENGTH            1280
#define MAX_AREAS                   2000
#define MAX_VNUM                    32767

#define BOOT_DB_ABORT_THRESHOLD     25
#define RUNNING_ABORT_THRESHOLD     10
#define ALARM_FREQUENCY             20

/*
 * Game parameters.
 * Increase the max'es if you add more of something.
 * Adjust the pulse numbers to suit yourself.
 */

#define STARTING_HP         500
#define MAX_CHUNK_WEIGHT        50
#define MAX_BUILDING_LEVEL      5
#define MAX_color           10                              /* eg look, prompt, shout */
#define MAX_ANSI            32                              /* eg red, black, etc */
#define MAX_ALIASES          5
#define MAX_ALLIANCE             15
#define MAX_IGNORES          3
#define MAX_CLASS            17
#define MAX_OBJECT_VALUES        15
#define MAX_BUILDON          6
#define MAX_SKILL           15
#define MAX_LEVEL            90
#define LEVEL_HERO                 (80)
#define LEVEL_GUIDE                  79
#define LEVEL_IMMORTAL               80
#define MAX_QUOTE       200
#define MAX_MAPS        1000
#define MIN_LOAD_OBJ        1000
#define MAX_LOAD_OBJ        1164
#define MAX_HELPER      13
#define BORDER_SIZE     3

#define TERRAIN_NONE        0
#define TERRAIN_BALANCED    1
#define TERRAIN_MOON        2
#define TERRAIN_FOREST      3
#define TERRAIN_ROUGH       4
#define TERRAIN_FROST       5
#define TERRAIN_SAND        6
#define TERRAIN_FIRE        7

#define SPACE_SIZE  450

#define Z_UNDERGROUND   0
#define Z_GROUND    1
#define Z_AIR       2
#define Z_SPACE     3
#define Z_PAINTBALL 4
#define Z_MAX       5
#define Z_NEWBIE    Z_MAX

#define MAX_AMMO    42
#define DAMAGE_ENVIRO   -3
#define DAMAGE_GENERAL  -1
#define DAMAGE_BULLETS  1
#define DAMAGE_BLAST    2
#define DAMAGE_ACID 3
#define DAMAGE_FLAME    4
#define DAMAGE_LASER    5
#define DAMAGE_PAINT    6
#define DAMAGE_SOUND    7
#define DAMAGE_PSYCHIC  8
#define DAMAGE_EMP  9

#define ITEM_IRON   0
#define ITEM_SKIN   1
#define ITEM_COPPER 2
#define ITEM_GOLD   3
#define ITEM_SILVER 4
#define ITEM_ROCK   5
#define ITEM_STICK  6
#define ITEM_LOG    7

#define STATE_SOLID     0
#define STATE_LIQUID        1
#define STATE_GAS       2

#define ELEMENT_CINNABAR_ORE    0
#define ELEMENT_MERCURY     1
#define ELEMENT_GRASS       2
#define ELEMENT_SOIL        3
#define ELEMENT_LEAD        4
#define ELEMENT_SALT        5
#define ELEMENT_SODIUM      6
#define ELEMENT_THORIUM     7

#define VEHICLE_JEEP            0
#define VEHICLE_TANK            1
#define VEHICLE_AIRCRAFT        2
#define VEHICLE_TRUCK           3
#define VEHICLE_CHINOOK         4
#define VEHICLE_BOMBER          5
#define VEHICLE_BBQ         6
#define VEHICLE_LASER           7
#define VEHICLE_MECH            8
#define VEHICLE_SCOUT           9
#define VEHICLE_FIGHTER         10
#define VEHICLE_FRIGATE         11
#define VEHICLE_BATTLECRUISER       12
#define VEHICLE_DESTROYER       13
#define VEHICLE_STARBASE        14
#define VEHICLE_XRAY            15
#define VEHICLE_ALIEN_SCOUT     16
#define VEHICLE_BIO_FLOATER     17
#define VEHICLE_CREEPER         18
#define MAX_VEHICLE         19

#define VEHICLE_FIRE_RESISTANT      BIT_1
#define VEHICLE_EXPLOSIVE       BIT_2
#define VEHICLE_FLOATS          BIT_3
#define VEHICLE_EATS_FUEL       BIT_4
#define VEHICLE_REGEN           BIT_5
#define VEHICLE_CORROSIVE       BIT_6
#define VEHICLE_CORROSIVE_A     BIT_7
#define VEHICLE_MINING_BEAM     BIT_8
#define VEHICLE_GUARD_LASERS        BIT_9
#define VEHICLE_PSI_SCANNER     BIT_10
#define VEHICLE_OBJ_SENSORS     BIT_11
#define VEHICLE_DRILL           BIT_12
#define VEHICLE_ALIEN_MAGNET        BIT_13
#define VEHICLE_TREASURE_BEAM       BIT_14
#define VEHICLE_SPACE_SCANNER       BIT_15

#define VEHICLE_STATE_NORMAL        0
#define VEHICLE_STATE_EVADE     1
#define VEHICLE_STATE_DEFENSE       2
#define VEHICLE_STATE_OFFENSE       3
#define VEHICLE_STATE_CHARGE        4
#define POWER_SOURCE            0
#define POWER_ENGINE            1
#define POWER_WEAPONS           2
#define POWER_ARMOR         3
#define POWER_REPAIR            4
#define POWER_MAX           5
#define SECTION_CONTROL_ROOM        0
#define SECTION_ENGINE_ROOM     1
#define SECTION_SENSOR_ROOM     2
#define SECTION_SHIELD_ROOM     3

#define RES_WEAPON          5
#define RES_ARMOR           6
#define RES_SHIP            7
#define RESEARCH_W_LASER_1      BIT_1
#define RESEARCH_W_LASER_2      BIT_2
#define RESEARCH_W_LASER_3      BIT_3
#define RESEARCH_W_PLASMA_1     BIT_4
#define RESEARCH_W_PLASMA_2     BIT_5
#define RESEARCH_W_PLASMA_3     BIT_6
#define RESEARCH_W_TORPEDO_1        BIT_7
#define RESEARCH_W_TORPEDO_2        BIT_8
#define RESEARCH_W_TORPEDO_3        BIT_9
#define RESEARCH_W_ION_1        BIT_10
#define RESEARCH_W_ION_2        BIT_11
#define RESEARCH_W_ION_3        BIT_12

#define RESEARCH_A_STEEL_1      BIT_1
#define RESEARCH_A_STEEL_2      BIT_2
#define RESEARCH_A_STEEL_3      BIT_3
#define RESEARCH_A_TITANIUM_1       BIT_4
#define RESEARCH_A_TITANIUM_2       BIT_5
#define RESEARCH_A_TITANIUM_3       BIT_6
#define RESEARCH_A_ALIEN_1      BIT_7
#define RESEARCH_A_ALIEN_2      BIT_8
#define RESEARCH_A_ALIEN_3      BIT_9

#define RESEARCH_S_SCOUT        BIT_1
#define RESEARCH_S_FRIGATE      BIT_2
#define RESEARCH_S_FIGHTER      BIT_3
#define RESEARCH_S_BATTLECRUISER    BIT_4
#define RESEARCH_S_DESTROYER        BIT_5
#define RESEARCH_S_STARBASE     BIT_6

#define SPEC_BLIND      100
#define SPEC_BARIN      30
#define SPEC_SLOW       50
#define SPEC_BLDHEAL        60
#define SPEC_EMP        90
#define SPEC_CONFUSE        120
#define SPEC_ANTIVIR        200
#define SPEC_WARP       300

#define EFFECT_BLIND        BIT_1
#define EFFECT_BARIN        BIT_2
#define EFFECT_SLOW     BIT_3
#define EFFECT_RESOURCEFUL  BIT_4
#define EFFECT_BOMBER       BIT_5
#define EFFECT_CONFUSE      BIT_6
#define EFFECT_POSTAL       BIT_7
#define EFFECT_ENCRYPTION   BIT_8
#define EFFECT_VISION       BIT_9
#define EFFECT_RUNNING      BIT_10
#define EFFECT_TRACER       BIT_11
#define EFFECT_WULFSKIN     BIT_12
#define EFFECT_DRUNK        BIT_13

#define SUIT_NONE           0
#define SUIT_WARP           1
#define SUIT_JUMP           2

#define WEAPON_BLINDING         BIT_4
#define WEAPON_POISON           BIT_5
#define WEAPON_HITS_AIR         BIT_6
#define WEAPON_CONFUSING        BIT_7
#define WEAPON_ALCOHOL          BIT_8

#define INST_NONE           0
#define INST_GPS            BIT_1
#define INST_REFLECTOR          BIT_2
#define INST_INTERN_DEF         BIT_3
#define INST_SATELLITE_UPLINK       BIT_4
#define INST_LASER_AIMS         BIT_5
#define INST_SAFEHOUSE          BIT_6
#define INST_PULSE_NEUTRALIZER      BIT_7
#define INST_DEPLEATED_URANIUM      BIT_8
#define INST_RESOURCE_PURIFIER      BIT_9
#define INST_ANTIVIRUS          BIT_10
#define INST_FIREWALL           BIT_11
#define INST_STUN_GUN           BIT_12
#define INST_PROCESSOR_UPGRADE      BIT_13
#define INST_SPOOF          BIT_14
#define INST_QP             BIT_15
#define INST_ORGANIC_CORE       BIT_16
#define INST_VIRAL_ENHANCER     BIT_17
#define INST_ALIEN_TECHNOLOGY       BIT_18
#define INST_ACID_DEFENSE       BIT_19
#define INST_ALIEN_HIDES        BIT_20

#define GUNNER_NUCLEAR          BIT_1                       //Adds nuclear fallout to EQ
#define GUNNER_POISON           BIT_2                       //Adds poison effect
#define GUNNER_ROCKETS          BIT_3                       //Stronger vs buildings
#define GUNNER_PSYCHIC          BIT_4                       //Pushes around randomly
#define GUNNER_CHAOS            BIT_5                       //Random effect
#define GUNNER_TRACER           BIT_6                       //Trace effect - always shows up on "where"

#define IMPLANT_METAL_CHEST_1       BIT_1
#define IMPLANT_METAL_CHEST_2       BIT_2
#define IMPLANT_METAL_CHEST_3       BIT_3
#define IMPLANT_METAL_ARM_1     BIT_4
#define IMPLANT_METAL_ARM_2     BIT_5
#define IMPLANT_METAL_ARM_3     BIT_6
#define IMPLANT_METAL_ABS_1     BIT_7
#define IMPLANT_METAL_ABS_2     BIT_8
#define IMPLANT_METAL_ABS_3     BIT_9

#define PIT_BORDER_X            (MAX_MAPS-10)
#define PIT_BORDER_Y            (MAX_MAPS-10)
#define MEDAL_BORDER_X          52
#define MEDAL_BORDER_Y          22

/*
 * Extended bitvector stuff.
 */
// #define INT_BITS                   32
#define INT_BITS                   64
#define XBM                        31
#define RSV                         5                       /* log2( INT_BITS )     */
#define XBI                         2                       /* int's in a bitvector */
#define MAX_BITS                  ( XBI * INT_BITS )

#define TYPE_UNDEFINED  -1

#define C_TYPE_MISC     0
#define C_TYPE_COMM     1
#define C_TYPE_CONFIG   2
#define C_TYPE_INFO     3
#define C_TYPE_ACTION   4
#define C_TYPE_OBJECT   5
#define C_TYPE_ALLI 6
#define C_TYPE_IMM  7

#define C_SHOW_NEVER    -1
#define C_SHOW_ALWAYS     0
#define C_SHOW_SKILL      1

#define PULSE_PER_SECOND     8
#define PULSE_VIOLENCE    (  2 * PULSE_PER_SECOND )
#define PULSE_OBJFUN      (  4 * PULSE_PER_SECOND )
#define PULSE_TICK        ( 60 * PULSE_PER_SECOND )
#define PULSE_ROOMS       ( 10 * PULSE_PER_SECOND )
#define PULSE_AREA        ( 80 * PULSE_PER_SECOND )
#define PULSE_AUCTION     ( 30 * PULSE_PER_SECOND )
#define PULSE_BACKUP      ( 1800 * PULSE_PER_SECOND )
#define PULSE_TIME        ( 3600 * PULSE_PER_SECOND )
#define PULSE_REMAP       ( 7200 * PULSE_PER_SECOND )
#define PULSE_OBJECTS     ( PULSE_PER_SECOND * 5 )
#define PULSE_BOMB        ( PULSE_PER_SECOND )
#define PULSE_QUEST   ( 15 * PULSE_PER_SECOND )
#define PULSE_SPEC        ( PULSE_PER_SECOND * 10 )

/*
 * Well known object virtual numbers.
 * Defined in #OBJECTS.
 */
#define OBJ_VNUM_MATERIAL   32699
#define OBJ_VNUM_TELEPORTER 32698
#define OBJ_VNUM_LOCATOR    32678
#define OBJ_VNUM_BLUEPRINTS 32693
#define OBJ_VNUM_ACID_TURRET_U  32694
#define OBJ_VNUM_FIRE_TURRET_U  32696
#define OBJ_VNUM_LASER_TOWER_U  32697
#define OBJ_VNUM_IDUP       32695
#define OBJ_VNUM_ACID_SPRAY 1010
#define OBJ_VNUM_CANNONBALL 32686
#define OBJ_VNUM_GRANADE    1012
#define OBJ_VNUM_SUIT_WARP  1013
#define OBJ_VNUM_SUIT_JUMP  1144
#define OBJ_VNUM_SCUD       32687
#define OBJ_VNUM_FLASH_GRENADE  1030
#define OBJ_VNUM_REFLECTOR  1031
#define OBJ_VNUM_COOKIE_LAUNCH  1032
#define OBJ_VNUM_COOKIE_AMMO    1033
#define OBJ_VNUM_MAIN_BOARD 1039
#define OBJ_VNUM_ATOM_BOMB  32692
#define OBJ_VNUM_CORPSE     32691
#define OBJ_VNUM_FLAG       32690
#define OBJ_VNUM_DART_BOARD 32689
#define OBJ_VNUM_QP_TOKEN   32688
#define OBJ_VNUM_ELEMENT    32682
#define OBJ_VNUM_CHINESE_TEA    32685
#define OBJ_VNUM_SMOKE_BOMB 32684
#define OBJ_VNUM_POISON_TEA 32683
#define OBJ_VNUM_CONTAINER  1077
#define OBJ_VNUM_LEAD_BOMB  999
#define OBJ_VNUM_BLACK_POWDER   998
#define OBJ_VNUM_BIO_GRENADE    997
#define OBJ_VNUM_BURN_GRENADE   996
#define OBJ_VNUM_SAFEHOUSE_INST 995
#define OBJ_VNUM_RESOURCE_PURE  994
#define OBJ_VNUM_DEPLEATED_URA  993
#define OBJ_VNUM_PULSE_NEUTRAL  992
#define OBJ_VNUM_COMPUTER   10
#define OBJ_VNUM_ALLI_BOARD 10000
#define OBJ_VNUM_PAINT_GUN  32679
#define OBJ_VNUM_STUN_GUN   989
#define OBJ_VNUM_PROCESSOR_UP   987
#define OBJ_VNUM_DISK_V     1138
#define OBJ_VNUM_DISK_C     1139
#define OBJ_VNUM_DISK_F     1140
#define OBJ_VNUM_DISK_S     1141
#define OBJ_VNUM_DISK_P     1145
#define OBJ_VNUM_SHOCK_BOMB 1150
#define OBJ_VNUM_MEDAL      32676
#define OBJ_VNUM_TOOLKIT    32669
#define OBJ_VNUM_DIRTY_BOMB 986
#define OBJ_VNUM_SCAFFOLD   32667
#define OBJ_VNUM_BROKEN_BONE    509
#define OBJ_VNUM_AIR2GROUNDBOMB 32686

#define MAX_QUEST_ITEMS     20
#define QUEST_ITEM_COST     1000
#define MIN_QUEST_OBJ       2
#define MAX_QUEST_OBJ       14

#define helper0 "Remember to read the three main help files: Help getting started, Help FAQ, Help Suggestions."
#define helper1 "Trouble creating a vehicle? Read: Help vehicle requirements."
#define helper2 "Found a GPS, Satellite uplink, or another installation or blueprint? You can IDENTIFY it."
#define helper3 "The quest items don't move. It's the clues that change. You need to compare your map to the clue map."
#define helper4 "A @@ccyan@@N-colored base means that its owner is a newbie, and should not be attacked. Read Help Rules for more detail."
#define helper5 "You'll get these helper messages for the first hour of play time. Don't ignore them. The reason you can't turn them off is because 99% of the questions people ask are explained in the help files."
#define helper6 "You will be attacked, and you will lose your base. If that happens, don't give up, start over, and build better defenses."
#define helper7 "Remember, this is a PK MUD, so no whining about someone killing you. Just like other people can kill you, you can kill others."
#define helper8 "Don't forget to visit the website (And vote :P ) - fredrik.homelinux.org/Amnon (With the capital A)"
#define helper9 "Want custom text in your Flag on the who list? Just ask Amnon for it!"
#define helper10 "Getting spammed out (Disconnected)? You don't have to! Check out 'help spammed out' to find out about a program that can help you."
#define helper11 "Tired of your char? Want to recreate? Want to leave the game and never come back :( ? Use the pdelete command to delete your char."
#define helper12 "Players can create their OWN custom attacks! See 'help special' for info!"

/*
 * Well known room virtual numbers.
 * Defined in #ROOMS.
 */
#define ROOM_VNUM_WMAP                3
#define ROOM_VNUM_LIMBO               2
#define ROOM_VNUM_JAIL            1

#define C_SHOW_NEVER    -1
#define C_SHOW_ALWAYS     0
#define C_SHOW_SKILL      1

/*
 * God Levels
 */
#define L_GOD           MAX_LEVEL
#define L_SUP           L_GOD - 1
#define L_DEI           L_SUP - 1
#define L_ANG           L_DEI - 1
#define L_HER           L_ANG - 1

/*
 * Time and weather stuff.
 */
#define SUN_DARK                    0
#define SUN_RISE                    1
#define SUN_LIGHT                   2
#define SUN_SET                     3

#define SKY_CLOUDLESS               0
#define SKY_CLOUDY                  1
#define SKY_RAINING                 2
#define SKY_LIGHTNING               3
#define SKY_MAX             4

#define MOON_DOWN   0
#define MOON_RISE   1
#define MOON_LOW    2
#define MOON_PEAK   3
#define MOON_FALL   4
#define MOON_SET    5

#define MOON_NEW    0
#define MOON_WAX_CRE    1
#define MOON_WAX_HALF   2
#define MOON_WAX_GIB    3
#define MOON_FULL   4
#define MOON_WAN_GIB    5
#define MOON_WAN_HALF   6
#define MOON_WAN_CRE    7

/*
 * More Time and weather stuff. - Wyn
 */

/* Overall time */
#define HOURS_PER_DAY   24
#define DAYS_PER_WEEK    7
#define DAYS_PER_MONTH  30
#define MONTHS_PER_YEAR 10
#define DAYS_PER_YEAR   (DAYS_PER_MONTH * MONTHS_PER_YEAR)

/* PaB: Hours of the day */
/* Notes: Night is half of the day, so sunrise is 1/4 of the way
 * through the day, and sunset 3/4 of the day.
 */
#define HOUR_DAY_BEGIN      (HOURS_PER_DAY / 4 - 1)
#define HOUR_SUNRISE        (HOUR_DAY_BEGIN + 1)
#define HOUR_NOON           (HOURS_PER_DAY / 2)
#define HOUR_SUNSET         ((HOURS_PER_DAY / 4) * 3 + 1)
#define HOUR_NIGHT_BEGIN    (HOUR_SUNSET + 1)
#define HOUR_MIDNIGHT       HOURS_PER_DAY

/* PaB: Seasons */
/* Notes: Each season will be arbitrarily set at 1/4 of the year.
 */
#define SEASON_WINTER       0
#define SEASON_SPRING       1
#define SEASON_SUMMER       2
#define SEASON_FALL         3
#define SEASON_MAX         4

/*
 * Connected state for a channel.
 */

/* These values referenced by users command, BTW */

#define CON_PLAYING                      0
#define CON_GET_NAME                     -1
#define CON_GET_OLD_PASSWORD             -2
#define CON_CONFIRM_NEW_NAME             -3
#define CON_GET_NEW_PASSWORD             -4
#define CON_CONFIRM_NEW_PASSWORD         -5
#define CON_READ_MOTD                   -10
#define CON_FINISHED                -12
#define CON_MENU                        -13
#define CON_COPYOVER_RECOVER            -14
/* For Hotreboot */
#define CON_QUITTING                  -15
#define CON_RECONNECTING                -16
#define CON_GET_NEW_CLASS       -17
#define CON_GET_ANSI            -18
#define CON_GET_RECREATION      -19
#define CON_GET_SEX         -20
#define CON_GET_BONUS           -21
#define CON_GET_NEW_PLANET      -22
#define CON_READ_RULES          -23
#define CON_GET_RESET           -24
#define CON_GET_NEW_MODE        -25
#define CON_SETTING_STATS             1

/*
 * TO types for act.
 */
#define TO_ROOM             0
#define TO_NOTVICT          1
#define TO_VICT             2
#define TO_CHAR             3

/*
 * Room flags.
 * Used in #ROOMS.
 */
#define ROOM_NO_MOB             BIT_3
#define ROOM_INDOORS            BIT_4

/*
 * Directions.
 * Used in #ROOMS.
 */
#define DIR_NORTH                     0
#define DIR_EAST                      1
#define DIR_SOUTH                     2
#define DIR_WEST                      3

/*
 * Sector types.
 * Used in #ROOMS.
 */

#define SECT_NULL                     0
#define SECT_MAX                   17

#define SECT_ROCK           1
#define SECT_SAND           2
#define SECT_HILLS          3
#define SECT_MOUNTAIN           4
#define SECT_WATER          5
#define SECT_SNOW           6
#define SECT_FIELD          7
#define SECT_FOREST         8
#define SECT_LAVA           9
#define SECT_BURNED         10
#define SECT_SNOW_BLIZZARD      11
#define SECT_ASH            12
#define SECT_AIR            13
#define SECT_UNDERGROUND        14
#define SECT_ICE            15
#define SECT_MAGMA          16

/*
 * Equpiment wear locations.
 * Used in #RESETS.
 */
#define WEAR_NONE               -1
#define WEAR_HEAD               0
#define WEAR_EYES       1
#define WEAR_FACE               2
#define WEAR_EAR_L              3
#define WEAR_EAR_R              4
#define WEAR_NECK_1             5
#define WEAR_NECK_2             6
#define WEAR_SHOULDERS          7
#define WEAR_ARMS               8
#define WEAR_WRIST_L            9
#define WEAR_WRIST_R            10
#define WEAR_HANDS              11
#define WEAR_FINGER_L           12
#define WEAR_FINGER_R           13
#define WEAR_HOLD_HAND_L        14
#define WEAR_HOLD_HAND_R        15
#define WEAR_ABOUT              16
#define WEAR_WAIST              17
#define WEAR_BODY               18
#define WEAR_LEGS               19
#define WEAR_FEET               20
#define MAX_WEAR                     21

/*
 * Positions.
 */
#define POS_DEAD                      0
#define POS_MORTAL                    1
#define POS_INCAP                     2
#define POS_STUNNED                   3
#define POS_SLEEPING                  4
#define POS_RESTING                   5
#define POS_SNEAKING                  6
#define POS_STANDING                  7
#define POS_WRITING                   8
#define POS_BUILDING                  9
#define POS_HACKING          10
#define POS_SPACE_COM            11
#define POS_ENGINEERING          12
#define POS_NUKEM            13
#define POS_PAGER            14

/*
 *  Configuration Bits for players
 */

#define CONFIG_SMALLMAP     BIT_1
#define CONFIG_QUESTS       BIT_2
#define CONFIG_EXITS        BIT_3
#define CONFIG_NOCOLORS     BIT_4
#define CONFIG_NOFOLLOW     BIT_5
#define CONFIG_COMBINE          BIT_6
#define CONFIG_PROMPT           BIT_7
#define CONFIG_TELNET_GA        BIT_8
#define CONFIG_COLOR            BIT_9
#define CONFIG_COMPRESS     BIT_10
#define CONFIG_FULL_ANSI        BIT_11
#define CONFIG_MXP      BIT_12
#define CONFIG_BLIND        BIT_13
#define CONFIG_PUBMAIL      BIT_14
#define CONFIG_LARGEMAP     BIT_15
#define CONFIG_MINCOLORS    BIT_16
#define CONFIG_SOUND        BIT_17
#define CONFIG_ECHAN        BIT_18
#define CONFIG_HELPER       BIT_19
#define CONFIG_CLIENT       BIT_20
#define CONFIG_BRIEF        BIT_21
#define CONFIG_IMAGE        BIT_22
#define CONFIG_COMPRESS2    BIT_23
#define CONFIG_TINYMAP      BIT_24
#define CONFIG_NOBLACK      BIT_25
#define CONFIG_WHITEBG      BIT_26
#define CONFIG_INVERSE      BIT_27
#define CONFIG_NOLEGEND     BIT_28

/*
 * ACT bits for players.
 */
#define PFLAG_AFK           BIT_1
#define PFLAG_SNOOP         BIT_2
#define PFLAG_PRACTICE          BIT_3
#define PFLAG_ALIAS         BIT_4
#define PFLAG_RAD_SIL           BIT_5
#define PFLAG_HELPING           BIT_6
#define PLR_PDELETER            BIT_7
#define PLR_BASIC           BIT_8
#define PLR_HOLYLIGHT                   BIT_13
#define PLR_WIZINVIS                    BIT_14
#define PLR_BUILDER                     BIT_15              /* Is able to use the OLC */
#define PLR_SILENCE                     BIT_16
#define PLR_NO_EMOTE                    BIT_17
#define PLR_NO_TELL                 BIT_19
#define PLR_LOG                     BIT_20
#define PLR_DENY                    BIT_21
#define PLR_FREEZE                  BIT_22
#define PLR_TAG             BIT_27                          /* For Tag */
#define PLR_ASS             BIT_28
#define PLR_INCOG           BIT_31

/*
 * Obsolete bits.
 */
#if 0
#define PLR_AUCTION                   4                     /* Obsolete     */
#define PLR_CHAT                    256                     /* Obsolete     */
#define PLR_NO_SHOUT             131072                     /* Obsolete     */
#endif

/*
 * Channel bits.
 */
#define CHANNEL_ALLIANCE        BIT_1
#define CHANNEL_GOSSIP          BIT_2
#define CHANNEL_MUSIC           BIT_3
#define CHANNEL_IMMTALK         BIT_4
#define CHANNEL_NEWBIE          BIT_5
#define CHANNEL_QUESTION        BIT_6
#define CHANNEL_SHOUT           BIT_7
#define CHANNEL_POLITICS        BIT_8
#define CHANNEL_FLAME           BIT_9
#define CHANNEL_ZZZ             BIT_10
#define CHANNEL_RACE            BIT_11
#define CHANNEL_CLAN            BIT_12
#define CHANNEL_NOTIFY          BIT_13
#define CHANNEL_INFO            BIT_14
#define CHANNEL_LOG     BIT_15
#define CHANNEL_CREATOR     BIT_16
#define CHANNEL_ALLALLI     BIT_17
#define CHANNEL_ALLRACE     BIT_18
#define CHANNEL_HERMIT      BIT_19                          /* Turns off ALL channels */
#define CHANNEL_BEEP        BIT_20
#define CHANNEL_FAMILY      BIT_21
#define CHANNEL_DIPLOMAT    BIT_22
#define CHANNEL_CRUSADE     BIT_23
#define CHANNEL_REMORTTALK  BIT_24
#define CHANNEL_HOWL            BIT_25
#define CHANNEL_ADEPT           BIT_26
#define CHANNEL_OOC             BIT_27
#define CHANNEL_QUEST           BIT_28
#define CHANNEL_CODE        BIT_29
#define CHANNEL_GAME        BIT_30

#define CHANNEL2_AFFIL      BIT_1
#define CHANNEL2_ALLAFFIL   BIT_2
#define CHANNEL2_PKOK       BIT_3
#define CHANNEL2_GUIDE      BIT_4
#define CHANNEL2_LANG       BIT_5

/* NOTE 32 is the last allowable channel ZEN */

/* Monitor channels - for imms to select what mud-based info they receive */
#define MONITOR_CONNECT     BIT_1
#define MONITOR_AREA_UPDATE BIT_2
#define MONITOR_AREA_BUGS   BIT_3
#define MONITOR_AREA_SAVING BIT_4
#define MONITOR_GEN_IMM     BIT_5
#define MONITOR_GEN_MORT    BIT_6
#define MONITOR_COMBAT      BIT_7
#define MONITOR_BUILD       BIT_8
#define MONITOR_OBJ     BIT_9
#define MONITOR_ROOM        BIT_10
#define MONITOR_BAD     BIT_11
#define MONITOR_DEBUG       BIT_12
#define MONITOR_SYSTEM      BIT_13
#define MONITOR_LDEBUG      BIT_14
#define MONITOR_FAKE        BIT_15

/* build bits for OLC -S- */
#define ACT_BUILD_NOWT                0                     /* not doing anything   */
#define ACT_BUILD_REDIT               1                     /* editing rooms        */
#define ACT_BUILD_OEDIT               2                     /* editing objects      */
#define ACT_BUILD_BEDIT               3                     /* editing buildings    */
#define ACT_BUILD_MPEDIT          4                         /* editing mprogs	*/
#define ACT_BUILD_CEDIT               5                     /* editing the clan table */
#define NO_USE             -999                             /* this table entry can	*/
/* NOT be used, except  */
/* by a Creator		*/

#define SEX_MALE                      1
#define SEX_FEMALE                    2

/*
 * Item types.
 * Used in #OBJECTS.
 */
#define ITEM_LIGHT                    1
#define ITEM_AMMO                     2
#define ITEM_BOMB                     3
#define ITEM_BLUEPRINT                4
#define ITEM_WEAPON                   5
#define ITEM_SUIT             6
#define ITEM_MEDPACK              7
#define ITEM_DRONE            8
#define ITEM_ARMOR                    9
#define ITEM_TELEPORTER          10
#define ITEM_INSTALLATION            11
#define ITEM_IMPLANT             12
#define ITEM_FLAG            13
#define ITEM_DART_BOARD          14
#define ITEM_ELEMENT             15
#define ITEM_CONTAINER           16
#define ITEM_WEAPON_UP           17
#define ITEM_PIECE           18
#define ITEM_COMPUTER            19
#define ITEM_LOCATOR             20
#define ITEM_SKILL_UP            21
#define ITEM_PART            22
#define ITEM_DISK            23
#define ITEM_TRASH           24
#define ITEM_ASTEROID            25
#define ITEM_BACKUP_DISK         26
#define ITEM_BOARD           27
#define ITEM_VEHICLE_UP          28
#define ITEM_TOOLKIT             29
#define ITEM_SCAFFOLD            30
#define ITEM_ORE             31
#define ITEM_BIOTUNNEL           32
#define ITEM_BATTERY             33
#define ITEM_TOKEN           35
#define ITEM_MATERIAL            40

/*
 * Extra flags.
 * Used in #OBJECTS.
 */
#define ITEM_NUCLEAR            1
#define ITEM_STICKY         2
#define ITEM_NOQP           4
#define ITEM_INVIS          32
#define ITEM_NODROP         128
#define ITEM_NOREMOVE           4096
#define ITEM_INVENTORY          8192
#define ITEM_NOSAVE         16384                           /* For "quest" items :) */
#define ITEM_RARE           1048576
#define ITEM_NOLOOT         4194304
#define ITEM_UNIQUE         16777216

#define CLASS_ENGINEER      0
#define CLASS_DARKOP        1
#define CLASS_MINER     2
#define CLASS_DRIVER        3
#define CLASS_SUICIDE_BOMBER    4
#define CLASS_PILOT     5
#define CLASS_SNIPER        6
#define CLASS_ROBOTIC       7
#define CLASS_SCIENTIST     8
#define CLASS_HACKER        9
#define CLASS_SCANNER       10
#define CLASS_SPRINTER      11
#define CLASS_PROJECTOR     12
#define CLASS_GENIUS        13
#define CLASS_MECHANIC      14
#define CLASS_MEDIC     15
#define CLASS_SPY       16

/*
 * Wear flags.
 * Used in #OBJECTS.
 */
#define ITEM_WEAR_NONE          BIT_0
#define ITEM_WEAR_HALO          BIT_1
#define ITEM_WEAR_AURA          BIT_2
#define ITEM_WEAR_HORNS         BIT_3
#define ITEM_WEAR_HEAD          BIT_4
#define ITEM_WEAR_FACE          BIT_5
#define ITEM_WEAR_BEAK          BIT_6
#define ITEM_WEAR_EAR           BIT_7
#define ITEM_WEAR_NECK          BIT_8
#define ITEM_WEAR_WINGS         BIT_9
#define ITEM_WEAR_SHOULDERS     BIT_10
#define ITEM_WEAR_ARMS          BIT_11
#define ITEM_WEAR_WRIST         BIT_12
#define ITEM_WEAR_HANDS         BIT_13
#define ITEM_WEAR_FINGER        BIT_14
#define ITEM_WEAR_CLAWS         BIT_15
#define ITEM_WEAR_HOLD_HAND     BIT_16
#define ITEM_WEAR_ABOUT         BIT_17
#define ITEM_WEAR_WAIST         BIT_18
#define ITEM_WEAR_BODY          BIT_19
#define ITEM_WEAR_TAIL          BIT_20
#define ITEM_WEAR_LEGS          BIT_21
#define ITEM_WEAR_FEET          BIT_22
#define ITEM_WEAR_HOOVES        BIT_23
#define ITEM_TAKE               BIT_24
#define ITEM_WEAR_EYES      BIT_26
#define ITEM_WEAR_CBADGE    BIT_27
#define ITEM_WEAR_UTAIL     BIT_28
/*
 * Apply types (for affects).
 * Used in #OBJECTS.
 */
#define APPLY_NONE                    0
#define APPLY_STR                     1
#define APPLY_DEX                     2
#define APPLY_INT                     3
#define APPLY_WIS                     4
#define APPLY_CON                     5
#define APPLY_SEX                     6
#define APPLY_CLASS                   7
#define APPLY_LEVEL                   8
#define APPLY_AGE                     9
#define APPLY_HEIGHT                 10
#define APPLY_WEIGHT                 11
#define APPLY_MANA                   12
#define APPLY_HIT                    13
#define APPLY_MOVE                   14
#define APPLY_GOLD                   15
#define APPLY_EXP                    16
#define APPLY_AC                     17
#define APPLY_HITROLL                18
#define APPLY_DAMROLL                19
#define APPLY_SAVING_PARA            20
#define APPLY_SAVING_ROD             21
#define APPLY_SAVING_PETRI           22
#define APPLY_SAVING_BREATH          23
#define APPLY_SAVING_SPELL           24

/*
 * Values for containers (value[1]).
 * Used in #OBJECTS.
 */
#define CONT_CLOSEABLE                1
#define CONT_PICKPROOF                2
#define CONT_CLOSED                   4
#define CONT_LOCKED                   8

/*
 * Data files used by the server.
 *
 * AREA_LIST contains a list of areas to boot.
 * All files are read in completely at bootup.
 * Most output files (bug, idea, typo, shutdown) are append-only.
 *
 * The NULL_FILE is held open so that we have a stream handle in reserve,
 *   so players can go ahead and telnet to all the other descriptors.
 * Then we close it whenever we need to open a file (e.g. a save file).
 */
#if defined(macintosh)
#define LOG_DIR         ""                                  /* Log files                 */
#define PLAYER_DIR      ""                                  /* Player files                 */
#define SITE_DIR    ""
#define NULL_FILE       "proto.are"                         /* To reserve one stream        */
#endif

#if defined(MSDOS)
#define LOG_DIR         ""                                  /* Log files                 */
#define PLAYER_DIR      ""                                  /* Player files                 */
#define SITE_DIR    ""
#define NULL_FILE       "nul"                               /* To reserve one stream        */
#endif

#if defined(unix)
#define PLAYER_DIR      "../player/"                        /* Player files                 */
#define LOG_DIR         "../log/"                           /* Log files                 */
#define SITE_DIR    "/var/www/orcs.biz/assault/"                    /* For online who list	*/
#define NULL_FILE       "/dev/null"                         /* To reserve one stream        */
#endif

#if defined(linux)
#define PLAYER_DIR      "../player/"                        /* Player files                 */
#define LOG_DIR         "../log/"                           /* Log files                 */
#define SITE_DIR    "/var/www/orcs.biz/assault/"
#define NULL_FILE       "/dev/null"                         /* To reserve one stream        */
#endif

#define AREA_LIST       "area.lst"                          /* List of areas                */

#define MAIL_DIR            "../mail/"
#define DATA_DIR            "../data/"
#define BUG_DIR             "../reports/"
#define LOG_DIR             "../log/"
#define INFO_DIR	    "../information/"

#define BUG_FILE            BUG_DIR  "bugs.txt"           /* Game bugs    */
#define CHANGES_FILE        DATA_DIR  "changes.txt"        /* For Changes list                 */
#define LOG_FILE            DATA_DIR  "logs.txt"           /* For 'idea', 'typo', and 'bug'    */
#define HELP_FILE           BUG_DIR   "helps.txt"                /* For missing help files      */
#define SNOOP_FILE          LOG_DIR  "watch.txt"                 /* For players who need to be watched   */
#define SHUTDOWN_FILE       BUG_DIR  "shutdown.txt"             /* For 'shutdown'               */
#define DISABLED_FILE       DATA_DIR "disabled.txt"             /* disabled commands - Wyn */
#define PLAYER_LIST_FILE    DATA_DIR "playerlist.txt"          /* Player list */

#define OBJECTS_FILE        DATA_DIR "objects.lst"
#define OBJECTS_FEST_FILE   DATA_DIR "objects.fst"
#define OBJECTS_BACKUP_FILE DATA_DIR "objects.bak"
#define QUOTE_FILE  DATA_DIR "quotes.txt"
#define BANS_FILE   DATA_DIR "bans.lst"
#define BRANDS_FILE DATA_DIR "brands.lst"
#define MAP_FILE    DATA_DIR "map.txt"
#define BUILDING_TABLE_FILE DATA_DIR "building_table.txt"
#define BUILDING_FILE   DATA_DIR "buildings.txt"
#define BUILDING_FEST_FILE  DATA_DIR "buildings.fst"
#define BUILDING_BACKUP_FILE    DATA_DIR "buildings.bak"
#define VEHICLE_FILE    DATA_DIR  "vehicles.txt"
#define VEHICLE_FEST_FILE   DATA_DIR  "vehicles.fst"
#define VEHICLE_BACKUP_FILE DATA_DIR  "vehicles.bak"
#define MAP_BACKUP_FILE DATA_DIR  "map.bak"
#define SCORE_FILE  DATA_DIR "scores.txt"
#define RANK_FILE   DATA_DIR "ranks.txt"
#define SYSDAT_FILE DATA_DIR "system.dat"
#define ALLIANCES_FILE  DATA_DIR "alliances.txt"
#define PLANET_FILE DATA_DIR "planets.txt"
#define MAX_PLAYERS_FILE DATA_DIR "players.txt"
#define MULTIPLAY_FILE  DATA_DIR "multiplay.txt"

/* Other Stuff - Flar */
#define COPYOVER_FILE   "COPYOVER.TXT"                      /* Temp data file used for copyover */
#define EXE_FILE        "../src/ack"                        /* The one that runs the ACK! */

/* stuff for Quests */
#define QROOM_VNUM "299"
#define CLAN_MONEY 1039

/***************************************************************************
 *  Original Diku Mud copyright (C) 1990, 1991 by Sebastian Hammer,        *
 *  Michael Seifert, Hans Henrik St{rfeldt, Tom Madsen, and Katja Nyboe.   *
 *                                                                         *
 *  Merc Diku Mud improvments copyright (C) 1992, 1993 by Michael          *
 *  Chastain, Michael Quan, and Mitchell Tse.                              *
 *                                                                         *
 *  Ack 2.2 improvements copyright (C) 1994 by Stephen Dooley              *
 *                                                                         *
 *  In order to use any part of this Merc Diku Mud, you must comply with   *
 *  both the original Diku license in 'license.doc' as well the Merc       *
 *  license in 'license.txt'.  In particular, you may not remove either of *
 *  these copyright notices.                                               *
 *                                                                         *
 *       _/          _/_/_/     _/    _/     _/    ACK! MUD is modified    *
 *      _/_/        _/          _/  _/       _/    Merc2.0/2.1/2.2 code    *
 *     _/  _/      _/           _/_/         _/    (c)Stephen Zepp 1998    *
 *    _/_/_/_/      _/          _/  _/             Version #: 4.3          *
 *   _/      _/      _/_/_/     _/    _/     _/                            *
 *                                                                         *
 *                                                                         *
 *  Much time and thought has gone into this software and you are          *
 *  benefitting.  We hope that you share your changes too.  What goes      *
 *  around, comes around.                                                  *
 ***************************************************************************/

#define DEC_UTILS_H 1

/* Use these for bitvectors..saves having to recalculate each time :) Zen */

#define     BIT_0       0
#define     BIT_1       (1 <<  0)                           /*          1 */
#define     BIT_2       (1 <<  1)                           /*          2 */
#define     BIT_3       (1 <<  2)                           /*          4 */
#define     BIT_4       (1 <<  3)                           /*	    8 */
#define     BIT_5       (1 <<  4)                           /*         16 */
#define     BIT_6       (1 <<  5)                           /*	   32 */
#define     BIT_7       (1 <<  6)                           /*	   64 */
#define     BIT_8       (1 <<  7)                           /*	  128 */
#define     BIT_9       (1 <<  8)                           /*	  256 */
#define     BIT_10      (1 <<  9)                           /*	  512 */
#define     BIT_11      (1 << 10)                           /*	 1024 */
#define     BIT_12      (1 << 11)                           /*	 2048 */
#define     BIT_13      (1 << 12)                           /*	 4096 */
#define     BIT_14      (1 << 13)                           /*	 8192 */
#define     BIT_15      (1 << 14)                           /*	16384 */
#define     BIT_16      (1 << 15)                           /*	32768 */
#define     BIT_17      (1 << 16)                           /*	65536 */
#define     BIT_18      (1 << 17)                           /*     131072 */
#define     BIT_19      (1 << 18)                           /*     262144 */
#define     BIT_20      (1 << 19)                           /*     524288 */
#define     BIT_21      (1 << 20)                           /*    1048576 */
#define     BIT_22      (1 << 21)                           /*    2097152 */
#define     BIT_23      (1 << 22)                           /*    4194304 */
#define     BIT_24      (1 << 23)                           /*    8388608 */
#define     BIT_25      (1 << 24)                           /*   16777216 */
#define     BIT_26      (1 << 25)                           /*   33554432 */
#define     BIT_27      (1 << 26)                           /*   67108864 */
#define     BIT_28      (1 << 27)                           /*  134217728 */
#define     BIT_29      (1 << 28)                           /*  268435456 */
#define     BIT_30      (1 << 29)                           /*  536870912 */
#define     BIT_31      (1 << 30)                           /* 1073741824 */
#define     BIT_32      (1 << 31)                           /* 2147483648 */
#define     BIT_33      4294967296                          /* (1 << 32) */
/* BIT_32 commented, it is the sign bit - Wyn */

#define mreturn(msg,ch) \
    { \
        send_to_char(msg,ch); \
        return; \
    }

/*
 *  SSM stuff
 */

#define STR(x) #x
#define SX(x) STR(x)
#define _caller __FILE__ ":" SX(__LINE__)

#define fread_string(x) _fread_string((x), _caller)
char *_fread_string args((FILE * fp, const char *caller));
#define str_dup(x) _str_dup((x), _caller)
char *_str_dup args((const char *str, const char *caller));
#define fread_string_eol(x) _fread_string_eol((x), _caller)
char *_fread_string_eol args((FILE * fp, const char *caller));
#define free_string(x) _free_string((x), _caller)
void _free_string args((char *pstr, const char *caller));

/*
 * Updated pointer referencing, curtesy of Spectrum, from Beyond the Veil
 *
 */

#define OBJ_NEXT          1
#define OBJ_NEXTCONTENT   2
#define OBJ_NULL          3

struct obj_ref_type
{
    bool inuse;
    struct obj_ref_type *next;
    OBJ_DATA **var;
    int type;                                               /* OBJ_xxxx */
};

#define CHAR_NEXT         1
#define CHAR_NEXTROOM     2
#define CHAR_NULL         3

struct char_ref_type
{
    bool inuse;
    struct char_ref_type *next;
    CHAR_DATA **var;
    int type;
};

#define OREF(v, type) do { \
        static struct obj_ref_type s={FALSE,NULL,NULL,type}; \
        s.var=&v; \
        obj_reference(&s); \
    } while(0)
#define OUREF(var) obj_unreference(&var);

#define CREF(v, type) do { \
        static struct char_ref_type s={FALSE,NULL,NULL,type}; \
        s.var=&v; \
        char_reference(&s); \
    } while(0)
#define CUREF(var) char_unreference(&var);

/*
 * Utility macros.
 */
#define UMIN(a, b)              ((a) < (b) ? (a) : (b))
#define UMAX(a, b)              ((a) > (b) ? (a) : (b))
#define URANGE(a, b, c)         ((b) < (a) ? (a) : ((b) > (c) ? (c) : (b)))
#define LOWER(c)                ((c) >= 'A' && (c) <= 'Z' ? (c)+'a'-'A' : (c))
#define UPPER(c)                ((c) >= 'a' && (c) <= 'z' ? (c)+'A'-'a' : (c))
#define IS_SET(flag, bit)       ((flag) & (bit))
#define SET_BIT(var, bit)       ((var) |= (bit))
#define REMOVE_BIT(var, bit)    ((var) &= ~(bit))
#define IS_LETTER(c)            ( ((c) >= 'A' && (c) <= 'Z' ) \
    ||((c) >= 'a' && (c) <= 'z' ) )

#define xMASK( bit )        ( 1 << ( ( bit ) & XBM ) )
#define xIS_SET( var, bit ) ( (var).bits[(bit) >> RSV] &   xMASK( bit ) )
#define xSET_BIT( var, bit )    ( (var).bits[(bit) >> RSV] |=  xMASK( bit ) )
#define xREMOVE_BIT( var, bit ) ( (var).bits[(bit) >> RSV] &= ~xMASK( bit ) )
#define xTOGGLE_BIT( var, bit ) ( (var).bits[(bit) >> RSV] ^=  xMASK( bit ) )
#define xIS_EMPTY( bit )     ( xbv_is_empty   ( &(bit) ) )
#define xSAME_BITS( var, bit )   ( xbv_same_bits  ( &(var), &(bit) ) )
#define xCLEAR_BITS( bit )   ( xbv_clear_bits ( &(bit) ) )
#define xSET_BITS( var, bit )    ( xbv_set_bits   ( &(var), &(bit) ) )
#define xREMOVE_BITS( var, bit ) ( xbv_remove_bits( &(var), &(bit) ) )

/*
 * Character macros.
 */

#define IS_NPC(ch)              (FALSE)
#define IS_GUIDE(ch)         (get_trust(ch) == LEVEL_GUIDE)
#define IS_IMMORTAL(ch)         (get_trust(ch) >= LEVEL_IMMORTAL)
#define IS_HERO(ch)             (get_trust(ch) >= LEVEL_HERO)
#define NOT_IN_ROOM(ch, victim) ( ch->x != victim->x || ch->y != victim->y || ch->z != victim->z )
#define IS_OUTSIDE(ch)      ( ( get_char_building(ch) ) ? TRUE : FALSE )
#define IS_NEWBIE(ch)       ((my_get_hours(ch,TRUE) <= 4 ))
#define IS_LINKDEAD(ch)     ((ch->desc) == NULL && !ch->fake )
#define IN_PIT(ch)      (ch->x > PIT_BORDER_X && ch->y > PIT_BORDER_Y && ch->z == Z_PAINTBALL)
#define IS_BUSY(ch)          ( ( ch->desc && ch->desc->connected == CON_PLAYING && ch->c_sn > -1 ) )
#define TRANSPORT_VEHICLE(type) (type == VEHICLE_TRUCK || type == VEHICLE_CHINOOK || type == VEHICLE_STARBASE)
#define AIR_VEHICLE(type)   (type == VEHICLE_AIRCRAFT || type == VEHICLE_CHINOOK || type == VEHICLE_BOMBER || type == VEHICLE_BIO_FLOATER )
#define continual_flight(vhc)   (AIR_VEHICLE(vhc->type) && vhc->type != VEHICLE_CHINOOK)
#define SPACE_VESSAL(vhc)   (vhc->type == VEHICLE_SCOUT || vhc->type == VEHICLE_FIGHTER || vhc->type == VEHICLE_FRIGATE || vhc->type == VEHICLE_BATTLECRUISER || vhc->type == VEHICLE_DESTROYER || vhc->type == VEHICLE_STARBASE || vhc->type == VEHICLE_ALIEN_SCOUT )
#define CIVILIAN(bld)       (build_table[bld->type].militairy == FALSE)
#define IS_AWAKE(ch)            (ch->position > POS_SLEEPING)
#define WAIT_STATE(ch, npulse)  ((ch)->wait = UMAX((ch)->wait, (npulse)))
#define IS_IMPLANTED(ch,bit)    (IS_SET(ch->implants,bit))
#define IS_BUGGED_AREA(x,y) ((x<0))
#define practicing(ch)      (IS_SET(ch->pcdata->pflags,PFLAG_PRACTICE) && ch->c_sn != gsn_practice )
#define paintball(ch)       ((ch->z == Z_PAINTBALL && ch->x >= 200 && ch->y >= 200 && ch->x <= 300 && ch->y <= 300))
#define medal(ch)       ((ch->z == Z_PAINTBALL && ch->x >= 1 && ch->x <= 52 && ch->y >= 1 && ch->y <= 22))
#define INVALID_COORDS(x,y) (( x < BORDER_SIZE || x > MAX_MAPS-BORDER_SIZE || y < BORDER_SIZE || y > MAX_MAPS-BORDER_SIZE ))
#define COMBAT_LAG(ch)      ((ch->fighttimer > 480))
#define NUKEM(ch)       ((ch->z == Z_PAINTBALL && ch->x == 2 && ch->y == 2))
#define blind_player(ch)    ((IS_SET(ch->config,CONFIG_BLIND)))
#define allied(ch,vch)      ((ch->pcdata->alliance != -1 && ch->pcdata->alliance == vch->pcdata->alliance))
/*
 * Object macros.
 */
#define OBJ_CAN_LOAD(obj,bld)   ((obj->level <= ((bld->level*20)-1)))
#define CAN_WEAR(obj, part)     (IS_SET((obj)->wear_flags,  (part)))
#define IS_OBJ_STAT(obj, stat)  (IS_SET((obj)->extra_flags, (stat)))
#define IS_WEAPON(obj)      (obj != NULL && (obj)->item_type == ITEM_WEAPON)
#define IS_SHIELD(obj)      ((obj)->item_type == ITEM_ARMOR && CAN_WEAR( obj, ITEM_WEAR_HOLD_HAND ))
#define COUNTS_TOWARDS_OBJECT_LIMIT(obj)    ((obj->item_type != ITEM_FLAG && obj->item_type != ITEM_BOARD ))

#define WAREHOUSE(bld)      ((bld->type == BUILDING_WAREHOUSE || bld->type == BUILDING_SECURE_WAREHOUSE))
#define GUNNER(bld)     ((bld->type == BUILDING_GUNNER))
/*
 * Description macros.
 */
#define PERS(ch, looker) ( can_see( looker, (ch) ) ? ch->name : IS_IMMORTAL( ch ) ? get_trust(ch) >= 90 ? "THE Mystical Beanlord" : "A Mystical Bean" : "Someone" )

#define NAME(ch)        ( (ch)->name )

/* Added stuff - Flar */
#define CH(descriptor)  ((descriptor)->original ? \
    (descriptor)->original : (descriptor)->character)

/*
 * Linked list macros, -- Altrag
 */
/* Regular linking of double-linked list */

#define LINK(link, first, last, next, prev) \
    do \
    { \
        if ( (link)->is_free == TRUE ) hang("LINK: link is FREE!"); \
        if ( (link)->is_free != FALSE ) hang("LINK: link is corrupted!"); \
        if ( (link)->prev || (link)->next ) hang("LINK: link already in list?"); \
        if ( (last) && (last)->next ) hang("LINK: last->next NON-NULL!"); \
        if ( !(first) ) \
        (first) = (link); \
        else \
        (last)->next = (link); \
        (link)->next = NULL; \
        (link)->prev = (last); \
        (last) = (link); \
    } while(0)

                        /* Link at the head of the list rather than the tail.  Double linked */
#define TOPLINK(link, first, last, next, prev) \
    do \
    { \
        if ( (link)->is_free == TRUE ) hang("TOPLINK: link is FREE!"); \
        if ( (link)->is_free != FALSE ) hang("TOPLINK: link is corrupted!"); \
        if ( (link)->prev || (link)->next ) hang("TOPLINK: link already in list?"); \
        if ( (first) && (first)->prev ) hang("TOPLINK: first->prev NON-NULL!"); \
        if ( !(last) ) \
        (last) = (link); \
        else \
        (first)->prev = (link); \
        (link)->prev = NULL; \
        (link)->next = (first); \
        (first) = (link); \
    } while(0)

                        /* Insert link before ref link */
#define LINK_BEFORE(link, ref, first, last, next, prev) \
    do \
    { \
        if ( (link)->is_free == TRUE ) hang("LINK_BEFORE: link is FREE!"); \
        if ( (link)->is_free != FALSE ) hang("LINK_BEFORE: link is corrupted!"); \
        if ( (link)->prev || (link)->next ) hang("LINK_BEFORE: link already in list?"); \
        if ( !(ref) ) hang("LINK_BEFORE: ref is NULL!"); \
        if ( (ref)->is_free == TRUE ) hang("LINK_BEFORE: ref is FREE!"); \
        if ( (ref)->is_free != FALSE ) hang("LINK_BEFORE: ref is corrupted!"); \
        (link)->next = (ref); \
        (link)->prev = (ref)->prev; \
        if ( !(ref)->prev ) \
        (first) = (link); \
        else \
        ((ref)->prev)->next = (link); \
        (ref)->prev = (link); \
    } while (0)

                                /* Insert link after ref link */
#define LINK_AFTER(link, ref, first, last, next, prev) \
    do \
    { \
        if ( (link)->is_free == TRUE ) hang("LINK_AFTER: link is FREE!"); \
        if ( (link)->is_free != FALSE ) hang("LINK_AFTER: link is corrupted!"); \
        if ( (link)->prev || (link)->next ) hang("LINK_AFTER: link already in list?"); \
        if ( !(ref) ) hang("LINK_AFTER: ref is NULL!"); \
        if ( (ref)->is_free == TRUE ) hang("LINK_AFTER: ref is FREE!"); \
        if ( (ref)->is_free != FALSE ) hang("LINK_AFTER: ref is corrupted!"); \
        (link)->prev = (ref); \
        (link)->next = (ref)->next; \
        if ( !(ref)->next ) \
        (last) = (link); \
        else \
        ((ref)->next)->prev = (link); \
        (ref)->next = (link); \
    } while (0)

                                /* Unlink a double linked list */
#define UNLINK(link, first, last, next, prev) \
    do \
    { \
        if ( (link)->is_free == TRUE ) hang("UNLINK: link is FREE!"); \
        if ( (link)->is_free != FALSE ) hang("UNLINK: link is corrupted!"); \
        if ( (link)->prev && (((link)->prev)->next != (link)) ) \
        hang("UNLINK: link->prev->next corrupted!"); \
        if ( (link)->next && (((link)->next)->prev != (link)) ) \
        hang("UNLINK: link->next->prev corrupted!"); \
        if ( !(link)->next ) \
        (last) = (link)->prev; \
        else \
        (link)->next->prev = (link)->prev; \
        if ( !(link)->prev ) \
        (first) = (link)->next; \
        else \
        (link)->prev->next = (link)->next; \
        (link)->prev = NULL; \
        (link)->next = NULL; \
    } while(0)
                                /* Link to the end of a single-linked list */
#define SING_LINK(link, first, next, DATA_TYPE) \
    do \
    { \
        if ( !(first) ) \
        (first) = (link); \
        else \
        { \
            DATA_TYPE *last; \
            for ( last = (first); last->next; last = last->next ) \
            ; \
            last->next = (link); \
        } \
        (link)->next = NULL; \
    } while(0)

            /* Link to head of a single-linked list (normal linking) */
#define SING_TOPLINK(link, first, next) \
    do \
    { \
        (link)->next = (first); \
        (first) = (link); \
    } while(0)

/* Unlink a single linked list */
#define SING_UNLINK(link, first, next, DATA_TYPE) \
    do \
    { \
        if ( (link) == (first) ) \
        (first) = (link)->next; \
        else \
        { \
            DATA_TYPE *prev; \
            for ( prev = (first); prev; prev = prev->next ) \
            if ( prev->next == (link) ) \
            break; \
            if ( prev != NULL ) \
            prev->next = (link)->next; \
            else \
            bug("Sing_unlink: link not in list.", 0); \
        } \
    } while(0)

                        /* Link to end of a half-linked list */
                                                                                                                                                                                    /* Half linked lists have a LAST pointer, but not a PREV pointer, making
                                                                                                                                                                                       them approximately halfway between a single linked list and a double
                                                                                                                                                                                       linked list. -- Altrag */
#define HALF_LINK(link, first, last, next) \
    do \
    { \
        if ( !(last) ) \
        (first) = (link); \
        else \
        (last)->next = (link); \
        (link)->next = NULL; \
        (last) = (link); \
    } while(0)

        /* Link to head of a half-linked list. */
#define HALF_TOPLINK(link, first, last, next) \
    do \
    { \
        if ( (last) == (first) ) \
        (last) = (link); \
        (link)->next = (first); \
        (first) = (link); \
    } while(0)

    /* Unlink a half-linked list. */
#define HALF_UNLINK(link, first, last, next, DATA_TYPE) \
    do \
    { \
        if ( (link) == (first) ) \
        { \
            (first) = (link)->next; \
            if ( (link) == (last) ) \
            (last) = NULL; \
        } \
        else \
        { \
            DATA_TYPE *prev; \
            for ( prev = (first); prev; prev = prev->next ) \
            if ( prev->next == (link) ) \
            break; \
            if ( prev != NULL ) \
            { \
                prev->next = (link)->next; \
                if ( (link) == (last) ) \
                (last) = prev; \
            } \
            else \
            bug("Half_unlink: link not in list.", 0); \
        } \
    } while(0)

                                /*
                                                                                                                                                                                                                                 * Miscellaneous macros.
                                                                                                                                                                                                                                 */

                                                                                                                                                                                                                                /* spec: macro-ised getmem as a wrapper around _getmem for mem_log handling */
#define getmem(size) _getmem(size,_caller,1)
#define qgetmem(size) _getmem(size,_caller,0)

                                                                                                                                                                                                                                /* This one goes as a #define in merc.h.. dont worry.. itll work.. :) */
                                                                                                                                                                                                                                /* spec: log all dispose's if mem_log==TRUE - also nuke trailing ; */
                                                                                                                                                                                                                                /* spec: add dispose override, too */
#define _dispose(mem,size,log) \
    do \
    { \
        if ( ! (mem) ) \
        { \
            bug("Disposing NULL memory",0); \
            return; \
        } \
        if (log&&mem_log) log_f("dispose(%p) from %s:%d", (mem), __FILE__, __LINE__); \
        free((mem)); \
        (mem) = NULL; \
    } while(0)

#define dispose(mem,size) _dispose(mem,size,1)
#define qdispose(mem,size) _dispose(mem,size,0)

        /*
                                                                                                                                                                                                                                         * Miscellaneous macros.
                                                                                                                                                                                                                                         */



/* Various linked lists head/tail pointer declarations. -- Altrag */
/***************************************************************************
 *  Original Diku Mud copyright (C) 1990, 1991 by Sebastian Hammer,        *
 *  Michael Seifert, Hans Henrik St{rfeldt, Tom Madsen, and Katja Nyboe.   *
 *                                                                         *
 *  Merc Diku Mud improvments copyright (C) 1992, 1993 by Michael          *
 *  Chastain, Michael Quan, and Mitchell Tse.                              *
 *                                                                         *
 *  Ack 2.2 improvements copyright (C) 1994 by Stephen Dooley              *
 *                                                                         *
 *  In order to use any part of this Merc Diku Mud, you must comply with   *
 *  both the original Diku license in 'license.doc' as well the Merc       *
 *  license in 'license.txt'.  In particular, you may not remove either of *
 *  these copyright notices.                                               *
 *                                                                         *
 *       _/          _/_/_/     _/    _/     _/    ACK! MUD is modified    *
 *      _/_/        _/          _/  _/       _/    Merc2.0/2.1/2.2 code    *
 *     _/  _/      _/           _/_/         _/    (c)Stephen Zepp 1998    *
 *    _/_/_/_/      _/          _/  _/             Version #: 4.3          *
 *   _/      _/      _/_/_/     _/    _/     _/                            *
 *                                                                         *
 *                        http://ackmud.nuc.net/                           *
 *                        zenithar@ackmud.nuc.net                          *
 *  Much time and thought has gone into this software and you are          *
 *  benefitting.  We hope that you share your changes too.  What goes      *
 *  around, comes around.                                                  *
 ***************************************************************************/


/*
 * All of the global linked lists, in one clump.  Declarations here,
 * actual variables in lists.c
 * -- Altrag
 */
extern  AREA_DATA *     first_area;
extern  AREA_DATA *     last_area;
extern  BAN_DATA *      first_ban;
extern  BAN_DATA *      last_ban;
extern  CHAR_DATA *     first_char;
extern  CHAR_DATA *     last_char;
extern  BUILDING_DATA *     first_building;
extern  BUILDING_DATA *     last_building;
extern  BUILDING_DATA *     first_active_building;
extern  BUILDING_DATA *     last_active_building;
extern  VEHICLE_DATA *      first_vehicle;
extern  VEHICLE_DATA *      last_vehicle;
extern  DESCRIPTOR_DATA *   first_desc;
extern  DESCRIPTOR_DATA *   last_desc;
extern  HELP_DATA *     first_help;
extern  HELP_DATA *     last_help;
extern  OBJ_DATA *      first_obj;
extern  OBJ_DATA *      last_obj;
extern  BOMB_DATA *         first_bomb;
extern  BOMB_DATA *         last_bomb;
extern  CONTROL_LIST    *   first_control_list;
extern  CONTROL_LIST    *   last_control_list;
extern  QUEUED_INTERACT_LIST *  first_queued_interact;
extern  QUEUED_INTERACT_LIST *  first_queued_interact;
extern  INFLUENCE_LIST  *   first_influence_list;
extern  INFLUENCE_LIST  *   last_influence_list;
extern  DL_LIST     *   first_brand;
extern  DL_LIST     *   last_brand;
extern  BOARD_DATA   *  first_board;
extern  BOARD_DATA   *  last_board;
extern  BUF_DATA_STRUCT * first_buf;
extern  BUF_DATA_STRUCT * last_buf;
extern  AREA_DATA *     area_free;
extern  BAN_DATA *      ban_free;
extern  CHAR_DATA *     char_free;
extern  DESCRIPTOR_DATA *   desc_free;
extern  HELP_DATA *     help_free;
extern  OBJ_DATA *      obj_free;
extern  OBJ_INDEX_DATA *    oid_free;
extern  ROOM_INDEX_DATA *   rid_free;
extern  PC_DATA *       pcd_free;
extern  BUILD_DATA_LIST *   build_free;
extern  INTERACT_DATA *     interact_free;
extern  INFLUENCE_DATA  *   influence_free;
extern  CONTROL_DATA    *   control_data_free;
extern  CONTROL_LIST    *   control_list_free;
extern  QUEUED_INTERACT_LIST *  queued_interact_free;
extern  INFLUENCE_LIST  *   influence_list_free;
extern  DL_LIST *       dl_list_free;
extern  BRAND_DATA *        brand_data_free;
extern BOARD_DATA   *   board_free;
extern MESSAGE_DATA *   message_free;
extern BUF_DATA_STRUCT * buf_free;
extern HASH_ENTRY * hash_free;
extern  BUILDING_DATA *     building_free;
extern VEHICLE_DATA *   vehicle_free;
extern QUEUE_DATA * queue_free;
extern BOMB_DATA *  bomb_free;
extern PAGER_DATA * pager_free;

extern void (*area_free_destructor )            ( AREA_DATA * adat );
extern void (*desc_free_destructor )            ( DESCRIPTOR_DATA * ddat );
extern void (*help_free_destructor )            ( HELP_DATA * hdat );
extern void (*build_free_destructor )           ( BUILD_DATA_LIST * bddat );
extern void (*interact_free_destructor )        ( INTERACT_DATA * idat );
extern void (*influence_free_destructor)        ( INFLUENCE_DATA * idat );
extern void (*control_data_free_destructor )    ( CONTROL_DATA * cdat );
extern void (*control_list_free_destructor )    ( CONTROL_LIST * cldat );
extern void (*queued_interact_free_destructor ) ( QUEUED_INTERACT_LIST * qildat );
extern void (*influence_list_free_destructor )  ( INFLUENCE_LIST * ildat );
extern void (*dl_list_free_destructor )         ( DL_LIST * dldat );
extern void (*board_free_destructor )           ( BOARD_DATA * bdat );
extern void (*buf_free_destructor )             ( BUF_DATA_STRUCT * bdat );
extern void (*hash_free_destructor )            ( HASH_ENTRY * hdat );

void bomb_free_destructor ( BOMB_DATA * bdat );
void queue_free_destructor ( QUEUE_DATA * qdat );
void pager_free_destructor ( PAGER_DATA * pdat );
void message_free_destructor ( MESSAGE_DATA * mdat );
void ban_free_destructor( BAN_DATA * bdat );
void oid_free_destructor( OBJ_INDEX_DATA * oidat );
void brand_data_free_destructor( BRAND_DATA * bdat );
void pcd_free_destructor( PC_DATA * pcdat );
void char_free_destructor( CHAR_DATA * cdat );
void obj_free_destructor( OBJ_DATA * odat );
void building_free_destructor( BUILDING_DATA * bdat );
void vehicle_free_destructor( VEHICLE_DATA * vdat );

#define GET_FREE(item, freelist) \
    do \
    { \
        if ( !(freelist) ) \
        (item) = getmem(sizeof(*(item))); \
        else \
        { \
            if ( !(freelist)->is_free ) \
            { \
                bug("GET_FREE: freelist head is NOT FREE!  Hanging...", 0); \
                for (;;); \
            } \
            (item) = (freelist); \
            (freelist) = (item)->next; \
            memset((item), 0, sizeof(*(item))); /* This clears is_free flag */ \
        } \
    } while(0)

#define PUT_FREE(item, freelist) \
    do \
    { \
        if ( (item)->is_free ) \
        { \
            bug("PUT_FREE: item is ALREADY FREE!  Hanging...", 0); \
            for (;;); \
        } \
        (item)->next = (freelist); \
        (item)->is_free = TRUE; /* This sets is_free flag */ \
        (freelist) = (item); \
        if (freelist##_destructor)  freelist##_destructor(item); \
    } while(0)



#include "strfuns.h"

#include "act_skills.h"
#include "mxp.h"
#include "web.h"
// MCCP
/* mccp: support bits */

#include <zlib.h>

#define TELOPT_COMPRESS 85
#define TELOPT_COMPRESS2 86

#define COMPRESS_BUF_SIZE 16384
// End MCCP
#if defined(KEY)
#undef KEY
#endif

#define KEY( literal, field, value )    if ( !str_cmp( word, literal ) ){field  = value;fMatch = TRUE;break;}

struct pager_data
{
    bool is_free;
    PAGER_DATA *next;
    PAGER_DATA *prev;
    char        * from;
    char        * msg;
    char        * time;
};
struct multiplay_type
{
    char * name;
    char * host;
};
struct ability_type
{
    char *name;
    sh_int engineering;
    sh_int building;
    sh_int combat;
    char *desc;
};
struct bomb_data
{
    bool is_free;
    BOMB_DATA *next;
    BOMB_DATA *prev;
    OBJ_DATA *obj;
};
struct queue_data
{
    bool is_free;
    QUEUE_DATA *next;
    char *command;
};
struct s_res_type
{
    char *name;
    int bit;
    sh_int type;
    int req;
    sh_int cost;
    int value;
    int value2;
    int value3;
    int level;
};

struct planet_type
{
    char *name;
    sh_int system;
    double gravity;
    sh_int  z;
    sh_int terrain;
    char * note;
};
struct load_type
{
    int     vnum;
    int     rarity;
    int     building;
};

struct alliance_type
{
    char    * name;
    int members;
    char    * leader;
    char    * history;
    int kills;
};

struct wildmap_type
{
    char * color;
    char * mark;
    char * cmark;
    char * name;
    sh_int    heat;
    sh_int    speed;
    sh_int    fuel;
};
struct formula_type
{
    int solid;
    int liquid;
    int gas;
    int vnum;
    int rank;
    char    * desc;
};
struct bonus_type
{
    char    * name;
    char    * desc;
    int item;
};
struct vehicle_data
{
    bool            is_free;
    VEHICLE_DATA    *next;
    VEHICLE_DATA    *prev;
    VEHICLE_DATA    *next_in_room;
    sh_int      type;
    char        *name;
    char        *desc;
    CHAR_DATA   *driving;
    VEHICLE_DATA    *vehicle_in;
    VEHICLE_DATA    *in_vehicle;
    BUILDING_DATA   *in_building;
    int     hit;
    int     max_hit;
    int     ammo_type;
    int     ammo;
    int     max_ammo;
    int     fuel;
    int     max_fuel;
    sh_int      speed;
    int     x;
    int     y;
    int     z;
    int     flags;
    int     timer;
    sh_int      range;
    sh_int      scanner;
    sh_int      state;
    int     power[POWER_MAX];
    int     value[1];                                       //V1 - Superweapon charge
};

struct skill_type
{
    char    * name;
    int gsn;
    bool    prof;
    char    * desc;
};
struct score_type
{
    char    * name;
    char    * killedby;
    int kills;
    int buildings;
    int time;
};
struct rank_type
{
    char    * name;
    int rank;
};
struct clip_type
{
    char    *name;
    int dam;
    int builddam;
    sh_int  miss;
    bool    explode;
    sh_int  speed;
    sh_int  type;
};
struct building_data
{
    bool        is_free;
    BUILDING_DATA   *next;
    BUILDING_DATA   *prev;
    BUILDING_DATA   *next_active;
    BUILDING_DATA   *prev_active;
    BUILDING_DATA   *next_owned;
    BUILDING_DATA   *prev_owned;
    int type;
    char *name;
    bool exit[4];
    int maxhp;
    int hp;
    int maxshield;
    int shield;
    int value[11];                                          //V0 Generate/Super. V1 Installation. V2 Saves HP (Practice). V3 Virus. V4 Safetimer.
    //V5 Space Weapon. V6 Space Armor. V7 Space Shiptype.  V8 Hacking tool. V9 Nuclear Fallout.
    //V10 Space Gold.
    int resources[8];
    char *owned;
    CHAR_DATA *owner;
    int x;
    int y;
    int z;
    sh_int level;
    bool visible;
    char    *attacker;
    bool active;
    sh_int protection;
    sh_int directories;
    sh_int real_dir;
    int password;
    int timer;
};

struct build_type
{
    int type;
    char *name;
    int hp;
    int shield;
    int resources[8];
    int requirements;
    int requirements_l;
    char *desc;
    char *symbol;
    sh_int buildon[MAX_BUILDON];
    bool militairy;
    int rank;
    sh_int act;
    sh_int max;
    bool disabled;
};
struct build_help_type
{
    char *help;
};

struct resource_color_type
{
    char *color;
};

struct map_type
{
    unsigned char  type[MAX_MAPS][MAX_MAPS][Z_MAX];
    signed char    resource[MAX_MAPS][MAX_MAPS][Z_MAX];
};

/*
 * Structure for extended bitvectors.
 */

struct bitvector_data
{
    long        bits[XBI];
};

struct str_array
{
    char *this_string;
};

struct sysdata_type
{
    bool w_lock;
    bool test_open;
    char *playtesters;
    STR_ARRAY imms[1];
    bool shownumbers;
    bool pikamod;
    sh_int  showhidden;
    bool killfest;
    bool p_lock;
    bool kill_groups;
    bool silent_reboot;
    int freemap;
    int qpmode;
    int xpmode;
};

struct ranking_type
{
    char            *   name;
    int                 rankfrom;
    int                 rankto;
};

struct changes_data
{
    char            *   coder;
    char            *   date;
    char            *   change;
    time_t              mudtime;
};

struct log_data
{
    char            *   reporter;
    char            *   type;
    char            *   date;
    char            *   log;
    bool                is_finished;
};

struct board_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    BOARD_DATA   *  next;
    BOARD_DATA   *  prev;
    int             vnum;
    MESSAGE_DATA *  first_message;
    MESSAGE_DATA *  last_message;
    int             min_read_lev;
    int             min_write_lev;
    int             expiry_time;
    int             clan;
};

struct message_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    MESSAGE_DATA *  next;
    MESSAGE_DATA *  prev;                                   /* Only used in save_board */
    BOARD_DATA   *  board;
    time_t          datetime;
    char         *  author;
    char         *  title;
    char         *  message;

};

struct charic_type
{
    char *   name;
};

/*
 * color look-up table structure thingy.
 */

struct color_type
{
    char *      name;                                       /* eg, gossip, say, look */
    int        index;                                       /* unique index */
};

struct ansi_type
{
    char *   name;
    char *   value;                                         /* escape sequence, or whatever */
    int      index;
    char         letter;
    int          stlen;
};

#define color_NORMAL "\033[0m"

#define NO_MATERIAL 10                                      /* Number of materials */

struct dl_list
{
    bool      is_free;
    DL_LIST * next;
    DL_LIST * prev;
    void *    this_one;
};

/*
 * Site ban structure.
 */
struct  ban_data
{
    bool    is_free;                                        /* Ramias:for run-time checks of LINK/UNLINK */
    BAN_DATA *  next;
    BAN_DATA *  prev;
    char *      name;
    char *  banned_by;
    char *  note;
    bool    newbie;
};

struct brand_data
{
    bool      is_free;
    BRAND_DATA *  next;
    BRAND_DATA *  prev;
    char *    branded;
    char *    branded_by;
    char *    dt_stamp;
    char *    message;
    char *    priority;
};

struct  time_info_data
{
    int         hour;
    int         day;
    int         month;
    int         year;
};


struct	weather_data
{
    int		mmhg;
    int		change;
    int		sky;
    int		sunlight;
};



/*
 * Descriptor (channel) structure.
 */
struct  descriptor_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    DESCRIPTOR_DATA *   next;
    DESCRIPTOR_DATA *   prev;
    DESCRIPTOR_DATA *   snoop_by;
    CHAR_DATA *         character;
    CHAR_DATA *         original;
    char *              host;
    sh_int              descriptor;
    sh_int              connected;
    bool                fcommand;
    char                inbuf           [4 * MAX_INPUT_LENGTH];
    char                incomm          [MAX_INPUT_LENGTH];
    char                inlast          [MAX_INPUT_LENGTH];
    int                 repeat;
    char *              showstr_head;
    char *              showstr_point;
    char *              outbuf;
    int                 outsize;
    int                 outtop;
    unsigned int    remote_port;                            /* 'Pair Port' ? -S- */
    int         check;                                      /* For new players*/
    int                 flags;
    int                 childpid;                           /* Child process id */
    time_t      timeout;
    // MCCP
    unsigned char   compressing;
    z_stream *          out_compress;
    unsigned char *     out_compress_buf;
    // End MCCP
    bool            mxp;                                    /* player using MXP flag */
};

#define DESC_FLAG_PASSTHROUGH 1                             /* Used when data is being passed to */
/*	Another prog.                     */
/*
 * Help table types.
 */
struct  help_data
{
    bool    is_free;                                        /* Ramias:for run-time checks of LINK/UNLINK */
    HELP_DATA * next;
    HELP_DATA * prev;
    sh_int      level;
    char *      keyword;
    char *      text;
};

/*
 * Per-class stuff.
 */
struct  class_type
{
    char        who_name        [4];                        /* Three-letter name for 'who'  */
    char     *  name;                                       /* Full name                    */
    char     *  desc;                                       /* Class Description		*/
    bool    rec;                                            /* Recommend class for newbies? */
    bool    rank;                                           /* Rank limit 			*/
};

/*
 * A kill structure (indexed by level).
 */
struct  kill_data
{
    sh_int              number;
    sh_int              killed;
};

/*
 * One character (PC or NPC).
 */
struct  char_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    bool        is_quitting;
    CHAR_DATA *         next;
    CHAR_DATA *     prev;
    CHAR_DATA *     next_in_room;
    CHAR_DATA *         leader;
    CHAR_DATA *         reply;
    BUILDING_DATA * first_building;
    ROOM_INDEX_DATA *   in_room;
    int         deaf;
    int                 poly_level;
    DESCRIPTOR_DATA *   desc;
    OBJ_DATA *          first_carry;
    OBJ_DATA *      last_carry;
    PC_DATA *           pcdata;
    char *              name;
    char *              prompt;
    char *              old_prompt;                         /* used to hold prompt when writing */
    char *      last_tell;
    sh_int              sex;
    sh_int      login_sex;
    sh_int              class;
    int         position;
    sh_int      level;
    sh_int      invis;                                      /* For wizinvis imms - lvl invis to */
    sh_int      incog;
    sh_int              trust;
    bool                wizbit;
    int                 played;
    int                 played_tot;
    time_t              logon;
    time_t              save_time;
    time_t              last_note;
    sh_int              timer;
    sh_int              wait;
    sh_int              hit;
    sh_int              max_hit;
    int                 act;
    int                 config;
    int                 act_build;                          /* for setting what ya editing */
    int                 build_vnum;                         /* the current vnum for w-y-e  */
    float              carry_weight;
    sh_int              carry_number;
    int         quest_points;                               /*As special rewards	 */
    BRAND_DATA  *   current_brand;
    BUILDING_DATA   * bvictim;
    sh_int       c_time;
    sh_int       c_sn;
    int          c_level;
    OBJ_DATA *   c_obj;
    CHAR_DATA *  victim;
    int      x;
    int      y;
    int      z;
    BUILDING_DATA * in_building;
    VEHICLE_DATA * in_vehicle;
    sh_int       fighttimer;
    sh_int       questtimer;
    sh_int       spectimer;
    sh_int       killtimer;
    int      medaltimer;
    sh_int map;
    bool security;
    char    * alias[5];
    char    * alias_command[5];
    int   implants;
    int   disease;
    int   effect;
    int   refund[8];
    bool      suicide;
    float     heat;
    bool    dead;
    sh_int  medals;
    bool    fake;
    sh_int  section;
    sh_int  kill_group;
    sh_int  c_count;
    int     game_points;                                    //For mannaroth's games. (We mean cheesly's)
};

/*
 * Data which only PC's have.
 */

struct  pc_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    PC_DATA *       next;
    PC_DATA *           prev;
    int         color[MAX_color];
    int         dimcol;
    int         hicol;
    char *              pwd;
    char *              bamfin;
    char *      room_enter;
    char *      room_exit;
    char *              bamfout;
    char *              title;
    char *              ranking;
    char *      host;                                       /* Used to tell PC last login site */
    sh_int      failures;                                   /* Failed logins */
    sh_int              pagelen;
    sh_int              o_pagelen;
    char        *       header;                             /* header used for message */
    char        *       message;                            /* message for board in progress */
    char    *   who_name;                                   /* To show on who name */
    int         pkills;
    int         bkills;
    int         tpkills;
    int         tbkills;
    int         deaths;
    int         blost;
    int         pbhits;
    int         pbdeaths;
    int         nukemwins;
    int                 pflags;
    char    *   lastlogin;
    int         monitor;                                    /* monitor channel for imms */
    char        *       ignore_list[MAX_IGNORES];           /* Ignore this person */
    int     hp_from_gain;                                   /* same for hitpoints */
    char *  pedit_state;
    char *  pedit_string[5];
    sh_int term_rows;
    sh_int term_columns;
    char * email_address;
    char *    load_msg;
    bool valid_email;
    bool    dead;
    bool    deleted;
    sh_int  skill[MAX_SKILL];
    sh_int  lastskill;
    int     alliance;
    QUEUE_DATA  * queue;
    QUEUE_DATA  * last_queue;
    int     reimb;
    int     prof_points;
    int     prof_ttl;
    int     spec_timer;
    int     spec_init;
    sh_int  set_exit;
    int     experience;
    //    bool	built[MAX_POSSIBLE_BUILDING];
    int     guess;
    PAGER_DATA  * pager;
};

struct  obj_index_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    OBJ_INDEX_DATA *    next;
    char *              owner;
    char *              name;
    sh_int              level;
    char *              short_descr;
    char *              description;
    sh_int              vnum;
    sh_int              item_type;
    int                 extra_flags;
    int                 wear_flags;
    int                 weight;
    int         building;
    int                 value   [MAX_OBJECT_VALUES];
    sh_int      heat;
    char *      image;
};

/*
 * One object.
 */
struct  obj_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    OBJ_DATA *          next;
    OBJ_DATA *      prev;
    OBJ_DATA *      next_in_carry_list;                     /* carry list is the list on a char, or in a container */
    OBJ_DATA *      prev_in_carry_list;
    OBJ_DATA *      first_in_carry_list;
    OBJ_DATA *      next_in_room;
    BOMB_DATA *     bomb_data;
    CHAR_DATA *         carried_by;
    CHAR_DATA *         attacker;
    OBJ_INDEX_DATA *    pIndexData;
    ROOM_INDEX_DATA *   in_room;
    char *              owner;
    char *              name;
    char *              short_descr;
    char *              description;
    int                 item_type;
    int                 extra_flags;
    int                 wear_flags;
    int                 wear_loc;
    int                 weight;
    sh_int              level;
    int                 value   [MAX_OBJECT_VALUES];
    int         x;
    int         y;
    int         z;
    BUILDING_DATA * in_building;
    sh_int      heat;
    int         quest_timer;
    sh_int      quest_map;
};

struct  area_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    AREA_DATA *         next;
    AREA_DATA *     prev;
    char *              name;
    int         offset;
    int                 modified;
    int                 min_vnum;
    int                 max_vnum;
    int                 area_num;
    char *              owner;
    char *              can_read;
    char *              can_write;
    char *              filename;
    int                 flags;
    int         aggro_list;
    BUILD_DATA_LIST *   first_area_room;
    BUILD_DATA_LIST *   last_area_room;
    BUILD_DATA_LIST *   first_area_help_text;
    BUILD_DATA_LIST *   last_area_help_text;
    BUILD_DATA_LIST *   first_area_object;
    BUILD_DATA_LIST *   last_area_object;
    BUILD_DATA_LIST *   first_area_objfunc;
    BUILD_DATA_LIST *   last_area_objfunc;
    char *      keyword;
};

struct  room_index_data
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    ROOM_INDEX_DATA *   next;
    AREA_DATA *         area;
    sh_int              vnum;
};

struct build_data_list                                      /* Used for storing area file data. */
{
    bool        is_free;                                    /* Ramias:for run-time checks of LINK/UNLINK */
    BUILD_DATA_LIST *    next;
    BUILD_DATA_LIST *    prev;
    void *               data;
};

struct lookup_type
{
    char *          text;
    bitset         value;
    int             cost;                                   /* if == NO_USE, only creators can set. */
};

struct  cmd_type
{
    char * const        name;
    DO_FUN *            do_fun;
    sh_int              position;
    sh_int              level;
    sh_int              log;
    sh_int              type;                               /*added by Aeria for do_commands*/
    sh_int              show;                               /*added by Aeria for do_commands*/
};

/*
 * Structure for a social in the socials table.
 */
struct  social_type
{
    char *         name;
    char *         char_no_arg;
    char *         others_no_arg;
    char *         char_found;
    char *         others_found;
    char *         vict_found;
    char *         char_auto;
    char *         others_auto;
};

/*
 * Disable struct - Wyn
 */
struct disabled_data
{
    DISABLED_DATA       *next;                              /* pointer to the next one */
    struct cmd_type const   *command;                       /* pointer to the command struct */
    char            *disabled_by;                           /* name of disabler */
    sh_int           dislevel;                              /* level of disabler */
    sh_int           uptolevel;                             /* level of execution allowed */
};

/* proto's for relevel crap */
#define RELEVEL_FILE    "../data/relevel.dat"
void do_saverelevel( void );
void do_loadrelevel( void );
void do_readrelevel( FILE * fp, RELEVEL_DATA * pRelevel );

/* Relevel DATA */
struct system_data {
   RELEVEL_DATA   * pRelevelList;
} rlvldata;

struct relevel_data {
   RELEVEL_DATA   * pNext;
   char           * strName;
   int              iLevel;
};

/* prototypes from db.c */
BOMB_DATA * make_bomb   args( ( OBJ_DATA *obj ) );
void    load_disabled   args( ( void ) );
void    save_disabled   args( ( void ) );
void  load_buildings_b  args( ( int mode ) );
void  load_vehicles     args( ( int mode ) );
void    load_building_t args( ( void ) );
void    reward_votes args( ( void ) );
/*
 * Extended bitvector utility functions, in handler.c.
 */
bool    xbv_is_empty    args( ( XBV *bits ) );
bool    xbv_same_bits   args( ( XBV *dest, const XBV *src ) );
void    xbv_clear_bits  args( ( XBV *bits ) );
void    xbv_set_bits    args( ( XBV *dest, const XBV *src ) );
void    xbv_remove_bits args( ( XBV *dest, const XBV *src ) );

/*
 * Our function prototypes.
 * One big lump ... this is every function in Merc.
 */
#define CD      CHAR_DATA
#define OD      OBJ_DATA
#define OID     OBJ_INDEX_DATA
#define RID     ROOM_INDEX_DATA
#define SF      SPEC_FUN
//#define OF	OBJ_FUN

/* act_clan.c */
void    load_clan_table args( ( void ) );
void    save_clan_table args( ( void ) );
void    load_map_data args(  ( void )  );

/* act_comm.c */
bool    can_multiplay   args( ( CHAR_DATA *ch ) );
void    add_follower    args( ( CHAR_DATA *ch, CHAR_DATA *master ) );
void    stop_follower   args( ( CHAR_DATA *ch ) );
void    die_follower    args( ( CHAR_DATA *ch ) );
void    send_to_loc        args( ( char *message, int x, int y, int z ) );
void    list_who_to_output   args(  ( void )   );

/* act_info.c */
void    set_title       args( ( CHAR_DATA *ch, char *title ) );
char *  color_string   args( ( CHAR_DATA *CH, char *argument ) );
void    display_details args( ( CHAR_DATA * viewer, CHAR_DATA *ch ) );
void    display_details_old args( ( CHAR_DATA * viewer, CHAR_DATA *ch ) );
void    show_building_info args( (CHAR_DATA *ch, int i) );

/* act_move.c */
void    move_char       args( ( CHAR_DATA *ch, int door ) );
void    crash       args( ( CHAR_DATA *ch, CHAR_DATA *attacker ) );
void    move        args( ( CHAR_DATA *ch, int x, int y, int z ) );
void    move_vehicle    args( ( VEHICLE_DATA *vhc, int x, int y, int z ) );
void    move_obj    args( ( OBJ_DATA *obj, int x, int y, int z ) );

/* act_obj.c */
void    get_obj     args( ( CHAR_DATA *ch, OBJ_DATA *obj, OBJ_DATA *container ) );
bool can_wear_at(CHAR_DATA * ch, OBJ_DATA * obj, int location);
void    wear_obj        args( ( CHAR_DATA *ch, OBJ_DATA *obj, bool fReplace ) );

/* board.c */
BOARD_DATA * load_board(OBJ_DATA * obj);
void    do_show_contents        args( ( CHAR_DATA *ch, OBJ_DATA * obj ) );
void    do_show_message         args( ( CHAR_DATA *ch, int mess_num, OBJ_DATA * obj ) );
void    do_edit_message     args( ( CHAR_DATA *ch, int mess_num, OBJ_DATA * obj ) );
void    do_add_to_message       args( ( CHAR_DATA *ch, char *argument ) );
void    do_start_a_message      args( ( CHAR_DATA *ch, char *argument ) );
void    save_message_data       args( ( void ) );
void    load_messages           args( ( void ) );

/* comm.c */
void    close_socket    args( ( DESCRIPTOR_DATA *dclose ) );
void    show_menu_to    args( ( DESCRIPTOR_DATA *d ) );     /* Main */
void    show_smenu_to   args( ( DESCRIPTOR_DATA *d ) );     /* Sex */
void    show_cmenu_to   args( ( DESCRIPTOR_DATA *d ) );     /* Class */
void    show_bmenu_to   args( ( DESCRIPTOR_DATA *d ) );     /* Bonus */
void   show_pmenu_to    args( ( DESCRIPTOR_DATA *d ) );     /* Planet */
void    write_to_buffer args( ( DESCRIPTOR_DATA *d, const char *txt,
int length ) );
void    send_to_char    args( ( const char *txt, CHAR_DATA *ch ) );
void    show_string     args( ( DESCRIPTOR_DATA *d, char *input ) );
void    act             args( ( const char *format, CHAR_DATA *ch,
const void *arg1, const void *arg2, int type ) );
void    hang            args( ( const char *str ) );

/* db.c */
void    load_sobjects   args( ( int mode ) );
void   perm_update args( ( void ) );
void    boot_db         args( ( bool fCopyOver ) );
void    area_update     args( ( void ) );
OD *    create_object   args( ( OBJ_INDEX_DATA *pObjIndex, int level ) );
BUILDING_DATA *    create_building   args( ( int type ) );
VEHICLE_DATA *     create_vehicle   args( ( int type ) );
void    clear_char      args( ( CHAR_DATA *ch ) );
void    free_char       args( ( CHAR_DATA *ch ) );
OID *   get_obj_index   args( ( int vnum ) );
RID *   get_room_index  args( ( int vnum ) );
char    fread_letter    args( ( FILE *fp ) );
int     fread_number    args( ( FILE *fp ) );
long_int fread_long_number args( ( FILE *fp ) );
char *  fread_string    args( ( FILE *fp ) );
void    fread_to_eol    args( ( FILE *fp ) );
char *  fsave_to_eol    args( ( FILE *fp ) );
char *  fread_word      args( ( FILE *fp ) );

/* void *  alloc_mem       args( ( int sMem ) );
void    check_freed     args( ( unsigned int first, unsigned int last) );
void    check_free_mem  args( ( void ) );
void *  alloc_perm      args( ( int sMem ) );
void    free_mem        args( ( void *pMem, int sMem ) );*/

/* spec: renamed getmem -> _getmem, nuked unused alloc_perm */
/* void *  alloc_perm      args( ( int sMem ) ); */
void *  _getmem     args( ( int size, const char *caller, int log ) );
void    dispose     args( ( void *mem, int size ) );
char *  str_dup         args( ( const char *str ) );
void    free_string     args( ( char *pstr ) );
int     number_fuzzy    args( ( int number ) );
int     number_range    args( ( int from, int to ) );
int     number_percent  args( ( void ) );
int     number_door     args( ( void ) );
int     number_bits     args( ( int width ) );
int     number_mm       args( ( void ) );
int     dice            args( ( int number, int size ) );
int     interpolate     args( ( int level, int value_00, int value_32 ) );
void    append_file     args( ( CHAR_DATA *ch, char *file, char *str ) );
void    bug             args( ( const char *str, int param ) );
void    log_string      args( ( const char *str ) );
void    tail_chain      args( ( void ) );
void    safe_strcat     args( ( int max_len, char * dest,char * source ) );
void    send_to_descrips args( ( const char *message ) );
void    bug_string      args( ( const char *str, const char *str2) );
/* Added stuff -Flar */
void    bugf (char * fmt, ...) __attribute__ ((format(printf,1,2)));
void    log_f (char * fmt, ...) __attribute__ ((format(printf,1,2)));

/* fight.c */
void    gain_exp    args( ( CHAR_DATA *ch, int value ) );
void    damage          args( ( CHAR_DATA *ch, CHAR_DATA *victim, int dam,
int dt ) );
void    damage_building args( ( CHAR_DATA *ch, BUILDING_DATA *bld, int dam ) );
void    damage_vehicle  args( ( CHAR_DATA *ch, VEHICLE_DATA *vhc, int dam, int dt ) );
void    update_pos      args( ( CHAR_DATA *victim ) );
void    raw_kill        args( ( CHAR_DATA *victim, char *argument ) );
void    set_fighting    args( ( CHAR_DATA *ch, CHAR_DATA *victim ) );
void    check_armor     args( ( OBJ_DATA *obj ) );
bool    check_dead  args( ( CHAR_DATA *ch, CHAR_DATA *victim ) );
void    pdie        args( ( CHAR_DATA *ch ) );
void    set_stun    args( ( CHAR_DATA *ch, int time ) );
bool    same_planet     args( (CHAR_DATA *ch, CHAR_DATA *vch ) );

/* handler.c */
void    activate_building   args( ( BUILDING_DATA *bld, bool on ) );
void    check_prof  args( ( CHAR_DATA *ch ) );
int count_users args( (OBJ_DATA *obj) );
bool    remove_obj  args( ( CHAR_DATA *ch, int iWear, bool fReplace ) );
int     get_trust       args( ( CHAR_DATA *ch               ) );
void    my_get_age  args( ( CHAR_DATA *ch, char * buf       ) );
int     my_get_hours    args( ( CHAR_DATA *ch, bool total ) );
int     my_get_minutes  args( ( CHAR_DATA *ch, bool total ) );
int     get_age         args( ( CHAR_DATA *ch ) );
int     can_carry_n     args( ( CHAR_DATA *ch ) );
int     can_carry_w     args( ( CHAR_DATA *ch ) );
void    char_from_room  args( ( CHAR_DATA *ch ) );
void    char_to_room    args( ( CHAR_DATA *ch, ROOM_INDEX_DATA *pRoomIndex ) );
void    char_to_building args( ( CHAR_DATA *ch, BUILDING_DATA *bld ) );
void    obj_to_char     args( ( OBJ_DATA *obj, CHAR_DATA *ch ) );
void    obj_from_char   args( ( OBJ_DATA *obj ) );
OD *    get_eq_char     args( ( CHAR_DATA *ch, int iWear ) );
void    equip_char      args( ( CHAR_DATA *ch, OBJ_DATA *obj, int iWear ) );
void    unequip_char    args( ( CHAR_DATA *ch, OBJ_DATA *obj ) );
int     count_obj_list  args( ( OBJ_INDEX_DATA *obj, OBJ_DATA *list ) );
int     count_obj_room  args( ( OBJ_INDEX_DATA *obj, OBJ_DATA *list ) );
void    obj_from_room   args( ( OBJ_DATA *obj ) );
void    obj_to_room     args( ( OBJ_DATA *obj, ROOM_INDEX_DATA *pRoomIndex ) );
void    obj_to_obj      args( ( OBJ_DATA *obj, OBJ_DATA *obj_to ) );
void    obj_from_obj    args( ( OBJ_DATA *obj ) );
void    extract_obj     args( ( OBJ_DATA *obj ) );
void    extract_building args( ( BUILDING_DATA *bld, bool msg ) );
void    extract_vehicle args( ( VEHICLE_DATA *vhc, bool msg ) );
void    extract_char    args( ( CHAR_DATA *ch, bool fPull ) );
void    extract_queue   args( ( QUEUE_DATA *q ) );
void    extract_pager   args( ( PAGER_DATA *p ) );
BUILDING_DATA *    get_char_building   args( ( CHAR_DATA *ch ) );
BUILDING_DATA *    get_obj_building    args( ( OBJ_DATA *obj ) );
BUILDING_DATA *    get_building      args( ( int x, int y, int z ) );
BUILDING_DATA *    get_building_range  args( ( int x, int y, int x2, int y2, int z ) );
VEHICLE_DATA * get_vehicle_char     args( ( CHAR_DATA *ch, char *argument ) );
VEHICLE_DATA *get_vehicle       args( ( char *argument, int x, int y, int z ) );
VEHICLE_DATA *get_vehicle_world     args( ( char *argument ) );
CD *    get_ch   args( ( char *argument ) );
CD *    get_char_room   args( ( CHAR_DATA *ch, char *argument ) );
CD *    get_char_world  args( ( CHAR_DATA *ch, char *argument ) );
CD *    get_char_area   args( ( CHAR_DATA *ch, char *argument ) );
CD *    get_char_loc      args( ( int x, int y, int z ) );
OD *    get_obj_loc       args( ( CHAR_DATA *ch, char *argument, int x, int y ) );
OD *    get_obj_type    args( ( OBJ_INDEX_DATA *pObjIndexData ) );
OD *    get_obj_list    args( ( CHAR_DATA *ch, char *argument,
OBJ_DATA *list ) );
OD *    get_obj_room    args( ( CHAR_DATA *ch, char *argument,
OBJ_DATA *list ) );
OD *    get_obj_carry   args( ( CHAR_DATA *ch, char *argument ) );
OD *    get_obj_wear    args( ( CHAR_DATA *ch, char *argument ) );
OD *    get_obj_here    args( ( CHAR_DATA *ch, char *argument ) );
OD *    get_obj_world   args( ( CHAR_DATA *ch, char *argument ) );
int     get_obj_number  args( ( OBJ_DATA *obj ) );
int     get_obj_weight  args( ( OBJ_DATA *obj           ) );
bool    can_see         args( ( CHAR_DATA *ch, CHAR_DATA *victim ) );
bool    can_see_obj     args( ( CHAR_DATA *ch, OBJ_DATA *obj    ) );
bool    can_drop_obj    args( ( CHAR_DATA *ch, OBJ_DATA *obj    ) );
bool    can_use         args( ( CHAR_DATA *ch, OBJ_DATA *obj    ) );
char *  who_can_use     args( ( OBJ_DATA *obj           ) );
void    info            args( ( char * message, int lv      ) );
void    log_chan    args( ( const char * message, int lv    ) );
CD   *  switch_char args( ( CHAR_DATA *victim, int mvnum, int poly_level ) );
CD   *  unswitch_char   args( ( CHAR_DATA *ch           ) );
void    monitor_chan    args( ( CHAR_DATA *ch, const char *message, int channel ) );
CD   *  get_char        args( ( CHAR_DATA *ch ) );
void char_reference args( (struct char_ref_type *ref) );
void char_unreference   args( (CHAR_DATA **var) );
void obj_reference  args( (struct obj_ref_type *ref) );
void obj_unreference    args( (OBJ_DATA **var) );
CHAR_DATA *get_rand_char args( ( int x, int y, int z ) );
int get_random_planet   args( ( void ) );

/* interp.c */
void    interpret       args( ( CHAR_DATA *ch, char *argument )   );
bool    is_number       args( ( char *arg )                       );
bool    check_social    args( ( CHAR_DATA *ch, char *command, char *argument ) );
void    add_to_queue    args( ( CHAR_DATA *ch, char *argument ) );
void    check_queue args( ( CHAR_DATA *ch ) );

// logs.c
void        load_changes        args( ( void ) );
void        save_changes        args( ( void ) );
void        delete_change       args( ( int num ) );
char    *   current_date        args( ( void ) );
int         num_changes         args( ( void ) );
void        load_logs           args( ( void ) );
void        save_logs           args( ( void ) );

/* macros.c */
void clear_basic    args( ( CHAR_DATA *ch ) );
int  count_buildings    args( ( CHAR_DATA *victim ) );
bool hidden     args( ( CHAR_DATA *victim ) );
bool open_bld       args( ( BUILDING_DATA *bld ) );
bool has_ability    args( ( CHAR_DATA *ch, int abil ) );
bool open_scaffold  args( (CHAR_DATA *ch, OBJ_DATA *obj) );
OBJ_DATA * make_quest_base args( ( int type, int size, int z ) );
void reset_building args( ( BUILDING_DATA *bld, int type ) );
void reset_special_building args( (BUILDING_DATA *bld) );
bool    ok_to_use   args( ( CHAR_DATA *ch, int value    ) );
void create_blueprint   args( ( BUILDING_DATA *bld ) );
bool complete       args( ( BUILDING_DATA *bld ) );
bool is_upgrade     args( ( int type ) );
bool is_neutral     args( ( int type ) );
bool is_evil        args( ( BUILDING_DATA *bld ) );
int get_char_cost   args( ( CHAR_DATA *ch ) );
bool IS_BETWEEN     args( ( int x, int x1, int x2 ) );
bool building_can_shoot args( ( BUILDING_DATA *bld, CHAR_DATA *ch, int range ) );
int  get_rank       args( ( CHAR_DATA *ch ) );
int  get_bit_value  args( ( int bit ) );
OBJ_DATA *create_material( int type );
VEHICLE_DATA *get_vehicle_from_vehicle( VEHICLE_DATA *vhc );
OBJ_DATA *create_teleporter( BUILDING_DATA *bld, int range );
OBJ_DATA *create_locator( int range );
bool sneak      args( ( CHAR_DATA *ch ) );
void check_building_destroyed args( (BUILDING_DATA *bld) );
int get_item_limit  args( ( BUILDING_DATA *bld ) );
OBJ_DATA *create_element( int type );
void send_warning   args( ( CHAR_DATA *ch, BUILDING_DATA *bld, CHAR_DATA *victim ) );
void update_ranks   args( ( CHAR_DATA *ch ) );
bool defense_building   args( ( BUILDING_DATA *bld ) );
void sendsound      args( ( CHAR_DATA *ch, char *file, int V, int I, int P, char *T, char *filename ) );
int check_dodge     args( ( CHAR_DATA *ch, int chance ) );
bool in_range       args(( CHAR_DATA *ch, CHAR_DATA *victim, int range ));
int get_ship_range  args( ( VEHICLE_DATA *vhc ) );
int get_ship_weapon_range   args( ( VEHICLE_DATA *vhc ) );
bool ok_moon        args( ( int sec ) );
void make_medal_base    args( ( CHAR_DATA *ch ) );
void create_obj_atch    args( ( CHAR_DATA *ch, int index ) );
bool blind_spot     args( ( CHAR_DATA *ch, int x, int y ) );
int get_armor_value args( ( int dt ) );
/*------*\ 
) save.c (
\*------*/
void    save_char_obj   args( ( CHAR_DATA *ch ) );
bool    load_char_obj   args( ( DESCRIPTOR_DATA *d, char *name, bool system_call ) );
void    save_objects    args( ( int mode ) );
void    save_map    args( ( void ) );
void    save_buildings  args( ( void ) );
void    save_vehicles   args( ( int mode ) );
void    save_scores args( ( void ) );
void    save_ranks  args( ( void ) );
void    save_multiplay  args( ( void ) );
void    save_planets    args( ( void ) );
void    fread_object    args( ( FILE * fp ) );
void    save_bans   args( ( void ) );
char    *initial    args( ( const char *str ) );
void   save_buildings_b args( ( int mode ) );
void    save_alliances  args( ( void ) );
void    save_building_table args( ( void ) );

/* social-edit.c  */

void load_social_table  args(  ( void )  );

/*---------*\ 
) trigger.c (
\*---------*/

void    trigger_handler args( ( CHAR_DATA *ch, OBJ_DATA *obj, int trigger ) );

/*--------*\ 
) update.c# (
\*--------*/
int get_user_seconds args(( void ));
void    explode     args( ( OBJ_DATA *obj ) );
void    update_handler  args( ( void )                                );
void    rooms_update    args( ( void ) );
void    building_update args( ( void ) );
void    init_alarm_handler args(  ( void ) );
void    alarm_update args( ( void ) );
void    building_update args( ( void ) );

/* write.c */
void    write_start     args( ( char * * dest, void * retfunc, void * retparm, CHAR_DATA * ch ) );
void    write_interpret args( ( CHAR_DATA * ch, char * argument ) );

/* build.c */
void  build_strdup(char * * dest,char * src,bool freesrc,CHAR_DATA * ch);
char * build_simpstrdup( char * buf);                       /* A plug in alternative to str_dup */
void build_save args( ( void ) );
extern const char * cDirs;
int  get_dir(char);
char * show_values( const struct lookup_type * table, int value, bool fBit );

/* buildtab.c  */
/*
int table_lookup	args( (const struct lookup_type * table,char * name) );
char * rev_table_lookup	args( (const struct lookup_type * table,int number) );
char * bit_table_lookup	args( (const struct lookup_type * table,int number) );
*/

/* buildare.c */
/* Area manipulation funcs in buildare.c */
int build_canread(AREA_DATA * Area,CHAR_DATA * ch,int showerror);
int build_canwrite(AREA_DATA * Area,CHAR_DATA * ch,int showerror);
#define AREA_NOERROR   0
#define AREA_SHOWERROR 1

/* areasave.c */
void area_modified(AREA_DATA *);
void build_save_flush(void);

/*    SSM   */
void temp_fread_string  args( (FILE * fp, char *buf) );
void save_brands    args( ( void ) );

/*
 *  sysdat.c
 */
void load_sysdata   args( ( void ) );
void save_sysdata   args( ( void ) );

// MCCP
/*
 * mccp.c
 */
bool compressStart(DESCRIPTOR_DATA *desc, unsigned char telopt);
bool compressEnd(DESCRIPTOR_DATA *desc,unsigned char type);
bool process_compressed(DESCRIPTOR_DATA *desc);
bool write_compressed(DESCRIPTOR_DATA *desc, char *txt, int length);
// End MCCP

/*
 * mxp.c
 */
void convert_mxp_tags (const int bMXP, char * dest, const char *src, int length);
int count_mxp_tags (const int bMXP, const char *txt, int length);
void turn_on_mxp (DESCRIPTOR_DATA *d);

// act_misc.c
void respawn_buildings args( (CHAR_DATA *ch) );
int get_loc args( ( char *loc ) );
bool can_build args( ( int type, int sect, int planet ) );
int parse_direction args( ( CHAR_DATA *ch, char *arg ) );

// act_alliance.c
void    do_pipe                 args( ( CHAR_DATA *ch, char *argument ) );

bool    upgradable      args( ( BUILDING_DATA *bld ) );

void    quest_update    args( ( void ) );
void draw_space( CHAR_DATA *ch );

// terrain.c
void create_map args( ( CHAR_DATA *ch, int type ) );
void create_special_map args( ( void ) );
void make_lava_river    args( (int x, int y, int z) );
void init_fields    args( ( void ) );

// games.c
void nuke_blow args( ( CHAR_DATA *ch ) );

//buildings.c
bool check_missile_defense args( (OBJ_DATA *obj) );

//web.c
void update_web_data    args( ( int type, char *value ) );
void generate_webpage   args( ( void ) );
void load_web_data  args( ( void ) );


#define descriptor_list first_desc

extern OBJ_DATA *map_obj[MAX_MAPS][MAX_MAPS];

extern CHAR_DATA * char_list;                               //for pload
extern BUILDING_DATA * building_list;
extern VEHICLE_DATA  * vehicle_list;
extern      int         MAX_BUILDING;

extern  bool            booting_up;
extern  bool      area_resetting_global;
extern char *  const   dir_name        [];
extern char *  const   rev_name        [];
extern int     const   order           [];
extern char *  const   helper          [MAX_HELPER];
extern int     const   prof_time       [];
extern char *  const   vehicle_name    [MAX_VEHICLE];
extern char *  const   vehicle_desc    [MAX_VEHICLE];

/*
 * Global constants.
 */
extern  const   struct  color_type     color_table    [MAX_color];
extern  const   struct   ansi_type  ansi_table  [MAX_ANSI];
extern  const   struct  class_type      class_table     [MAX_CLASS];
extern          struct  map_type    map_table;
extern          struct  alliance_type   alliance_table  [MAX_ALLIANCE];
extern          struct  score_type   score_table        [100];
extern          struct  rank_type   rank_table      [30];
extern const    struct  ranking_type ranking_table[];
extern  const   struct  cmd_type        cmd_table       [];
extern  const   struct  wildmap_type    wildmap_table   [SECT_MAX];
extern  struct  social_type      *social_table;
extern const    struct clip_type            clip_table[MAX_AMMO];
extern const    struct skill_type           skill_table[];
extern const    struct  bonus_type      bonus_table[];
extern const    struct formula_type formula_table[];
extern      struct load_type    load_list[MAX_BUILDING_LEVEL+1][50];
extern const    struct s_res_type   s_res_table[];
extern const    struct planet_type  planet_table[];
extern const    struct ability_type ability_table[];
extern          struct  multiplay_type   multiplay_table        [30];

extern          struct  build_type        build_table[MAX_POSSIBLE_BUILDING];
extern          struct  build_help_type   build_help_table[MAX_POSSIBLE_BUILDING];
//extern const    struct  build_type		build_table[MAX_BUILDING];
//extern const    struct  build_help_type		build_help_table[MAX_BUILDING];

/* spec: log all calls to getmem/dispose when set */
extern bool mem_log;

/*
 * Global variables.
 */
extern          char                    bug_buf         [];
extern          time_t                  current_time;
extern          bool                    fLogAll;
extern          FILE *                  fpReserve;
extern          KILL_DATA               kill_table      [];
extern          char                    log_buf         [];
extern          char                    testerbuf       [];
extern          TIME_INFO_DATA          time_info;
extern          WEATHER_DATA            weather_info[SECT_MAX];
extern          DESCRIPTOR_DATA   *     descriptor_list;
extern          CHAR_DATA         *     char_list;
extern          ROOM_INDEX_DATA   *     room_index_hash [ MAX_KEY_HASH ];
extern          OBJ_INDEX_DATA    *     obj_index_hash [ MAX_KEY_HASH ];
extern          SYS_DATA_TYPE            sysdata;
extern          BUILDING_DATA         *     building_list;
extern          VEHICLE_DATA          *     vehicle_list;
extern      CHAR_DATA *         map_ch[MAX_MAPS][MAX_MAPS][Z_MAX];
extern      BUILDING_DATA   *   map_bld[MAX_MAPS][MAX_MAPS][Z_MAX];
extern      VEHICLE_DATA    *   map_vhc[MAX_MAPS][MAX_MAPS][Z_MAX];
extern      OBJ_DATA    *   vehicle_weapon;
extern const    int         kill_groups[];
extern      int             quest_objs;
extern      OBJ_DATA    *   quest_obj[MAX_QUEST_ITEMS];
extern      long            building_count;

extern BOARD_DATA   *  first_board;
extern BOARD_DATA   *   last_board;
extern BOARD_DATA   *   board_free;
extern MESSAGE_DATA *   message_free;
extern QUEUE_DATA * queue_free;
extern BOMB_DATA *  bomb_free;
extern PAGER_DATA * pager_free;

extern          DISABLED_DATA     *     disabled_first;     /* interp.c */

extern char *history1;
extern char *history2;
extern char *history3;
extern char *history4;
extern char *history5;
extern char *history6;
extern char *history7;
extern char *history8;
extern char *history9;
extern char *history10;

/*
 * Command functions.
 * Defined in act_*.c (mostly).
 */

// MCCP
DECLARE_DO_FUN( do_compress );                              /* MCCP */
// End MCCP

DECLARE_DO_FUN( do_rename       );
DECLARE_DO_FUN( do_afk      );
DECLARE_DO_FUN( do_alias    );
DECLARE_DO_FUN( build_arealist  );
DECLARE_DO_FUN( do_ask          );
DECLARE_DO_FUN( do_bamfin       );
DECLARE_DO_FUN( do_bamfout      );
DECLARE_DO_FUN( do_beep     );
DECLARE_DO_FUN( do_colist   );
DECLARE_DO_FUN( do_color    );
DECLARE_DO_FUN( do_code     );
DECLARE_DO_FUN( do_creator  );
DECLARE_DO_FUN( do_edit     );
DECLARE_DO_FUN( do_enter    );
DECLARE_DO_FUN( do_finger   );
DECLARE_DO_FUN( do_flame        );
DECLARE_DO_FUN( do_gossip       );
DECLARE_DO_FUN( do_ooc          );
DECLARE_DO_FUN( do_politics     );
DECLARE_DO_FUN( do_game         );
DECLARE_DO_FUN( do_quest    );
DECLARE_DO_FUN( do_heal     );
DECLARE_DO_FUN( do_resetpassword);
DECLARE_DO_FUN( do_iscore       );
DECLARE_DO_FUN( do_isnoop       );
DECLARE_DO_FUN( do_iwhere       );
DECLARE_DO_FUN( do_monitor  );
DECLARE_DO_FUN( do_music        );
DECLARE_DO_FUN( do_newbie       );
DECLARE_DO_FUN( do_atalk        );
DECLARE_DO_FUN( do_nopray       );
DECLARE_DO_FUN( do_pemote       );
DECLARE_DO_FUN( do_pray         );
DECLARE_DO_FUN( do_respond      );
DECLARE_DO_FUN( do_scan         );
DECLARE_DO_FUN( do_status       );
DECLARE_DO_FUN( do_togbuild     );
DECLARE_DO_FUN( do_whisper      );
DECLARE_DO_FUN( do_whoname  );
DECLARE_DO_FUN( do_ranking  );
DECLARE_DO_FUN( do_disable  );
DECLARE_DO_FUN( game_interpret );
DECLARE_DO_FUN( build_interpret );
DECLARE_DO_FUN( hack_interpret  );
DECLARE_DO_FUN( engineering_interpret  );
DECLARE_DO_FUN( space_interpret );
DECLARE_DO_FUN( do_build        );
DECLARE_DO_FUN( do_delete       );
DECLARE_DO_FUN( do_read         );
DECLARE_DO_FUN( do_savearea     );
DECLARE_DO_FUN( do_write        );
DECLARE_DO_FUN( do_check_areas  );
DECLARE_DO_FUN( do_check_area   );
DECLARE_DO_FUN( do_ofindlev     );
DECLARE_DO_FUN( do_olist    );
DECLARE_DO_FUN( do_answer       );
DECLARE_DO_FUN( do_at           );
DECLARE_DO_FUN( do_auto         );
DECLARE_DO_FUN( do_pubmail  );
DECLARE_DO_FUN( do_sound    );
DECLARE_DO_FUN( do_ban          );
DECLARE_DO_FUN( do_blank        );
DECLARE_DO_FUN( do_bug          );
DECLARE_DO_FUN( do_channels     );
DECLARE_DO_FUN( do_combine      );
DECLARE_DO_FUN( do_commands     );
DECLARE_DO_FUN( do_config       );
DECLARE_DO_FUN( do_credits      );
DECLARE_DO_FUN( do_deny         );
DECLARE_DO_FUN( do_disarm       );
DECLARE_DO_FUN( do_disconnect   );
DECLARE_DO_FUN( do_drop         );
DECLARE_DO_FUN( do_east         );
DECLARE_DO_FUN( do_echo         );
DECLARE_DO_FUN( do_emote        );
DECLARE_DO_FUN( do_equipment    );
DECLARE_DO_FUN( do_examine      );
DECLARE_DO_FUN( do_follow       );
DECLARE_DO_FUN( do_force        );
DECLARE_DO_FUN( do_freeze       );
DECLARE_DO_FUN( do_get          );
DECLARE_DO_FUN( do_give         );
DECLARE_DO_FUN( do_goto         );
DECLARE_DO_FUN( do_help         );
DECLARE_DO_FUN( do_helplist     );
DECLARE_DO_FUN( do_holylight    );
DECLARE_DO_FUN( do_idea         );
DECLARE_DO_FUN( do_immtalk      );
DECLARE_DO_FUN( do_incog    );
DECLARE_DO_FUN( do_inventory    );
DECLARE_DO_FUN( do_invis        );
DECLARE_DO_FUN( do_log          );
DECLARE_DO_FUN( do_look         );
DECLARE_DO_FUN( do_memory       );
DECLARE_DO_FUN( do_noemote      );
DECLARE_DO_FUN( do_north        );
DECLARE_DO_FUN( do_note         );
DECLARE_DO_FUN( do_notell       );
DECLARE_DO_FUN( do_ofind        );
DECLARE_DO_FUN( do_oload        );
DECLARE_DO_FUN( do_oset         );
DECLARE_DO_FUN( do_ostat        );
DECLARE_DO_FUN( do_owhere       );
DECLARE_DO_FUN( do_pagelen      );
DECLARE_DO_FUN( do_password     );
DECLARE_DO_FUN( do_prompt       );
DECLARE_DO_FUN( do_purge        );
DECLARE_DO_FUN( do_question     );
DECLARE_DO_FUN( do_qui          );
DECLARE_DO_FUN( do_quote	);
DECLARE_DO_FUN( do_quit         );
DECLARE_DO_FUN( do_reboo        );
DECLARE_DO_FUN( do_reboot       );
DECLARE_DO_FUN( do_remove       );
DECLARE_DO_FUN( do_reply        );
DECLARE_DO_FUN( do_rest         );
DECLARE_DO_FUN( do_restore      );
DECLARE_DO_FUN( do_sacrifice    );
DECLARE_DO_FUN( do_save         );
DECLARE_DO_FUN( do_say          );
DECLARE_DO_FUN( do_osay     );
DECLARE_DO_FUN( do_score        );
DECLARE_DO_FUN( do_shutdow      );
DECLARE_DO_FUN( do_shutdown     );
DECLARE_DO_FUN( do_silence      );
DECLARE_DO_FUN( do_sla          );
DECLARE_DO_FUN( do_slay         );
DECLARE_DO_FUN( do_sleep        );
DECLARE_DO_FUN( do_snoop        );
DECLARE_DO_FUN( do_socials      );
DECLARE_DO_FUN( do_south        );
DECLARE_DO_FUN( do_stand        );
DECLARE_DO_FUN( do_tag      );
DECLARE_DO_FUN( do_tell         );
DECLARE_DO_FUN( do_time         );
DECLARE_DO_FUN( do_title        );
DECLARE_DO_FUN( do_transfer     );
DECLARE_DO_FUN( do_trust        );
DECLARE_DO_FUN( do_typo         );
DECLARE_DO_FUN( do_users        );
DECLARE_DO_FUN( do_wake         );
DECLARE_DO_FUN( do_wear         );
DECLARE_DO_FUN( do_west         );
DECLARE_DO_FUN( do_who          );
DECLARE_DO_FUN( do_wizhelp      );
DECLARE_DO_FUN( do_wizify       );
DECLARE_DO_FUN( do_wizlist      );
DECLARE_DO_FUN( do_wizlock      );
DECLARE_DO_FUN( do_yell         );
DECLARE_DO_FUN( do_otype );
DECLARE_DO_FUN( do_owear );
DECLARE_DO_FUN( do_ignore       );
DECLARE_DO_FUN( do_for      );
DECLARE_DO_FUN( do_hotreboo   );
DECLARE_DO_FUN( do_hotreboot      );
DECLARE_DO_FUN( do_olmsg    );
DECLARE_DO_FUN( do_scheck   );
DECLARE_DO_FUN( do_immbrand );
DECLARE_DO_FUN( do_sysdata );
DECLARE_DO_FUN( do_areasave );
DECLARE_DO_FUN( do_mapper );
DECLARE_DO_FUN( do_email );
DECLARE_DO_FUN( do_oflags );
DECLARE_DO_FUN( do_mine );
DECLARE_DO_FUN( do_use );
DECLARE_DO_FUN( do_setwcode  );
DECLARE_DO_FUN( do_a_build       );
DECLARE_DO_FUN( do_listbuildings       );
DECLARE_DO_FUN( do_killbuildin       );
DECLARE_DO_FUN( do_killbuilding       );
DECLARE_DO_FUN( do_bset       );
DECLARE_DO_FUN( do_relevel       );
DECLARE_DO_FUN( do_setrelevel       );
DECLARE_DO_FUN( do_load       );
DECLARE_DO_FUN( do_set         );
DECLARE_DO_FUN( do_arm         );
DECLARE_DO_FUN( do_highscores         );
DECLARE_DO_FUN( do_highranks );
DECLARE_DO_FUN( do_upgrade );
DECLARE_DO_FUN( do_makeexit );
DECLARE_DO_FUN( do_blast);
DECLARE_DO_FUN( do_warp );
DECLARE_DO_FUN( do_throw );
DECLARE_DO_FUN( do_activate );
DECLARE_DO_FUN( do_vload );
DECLARE_DO_FUN( do_exit );
DECLARE_DO_FUN( do_demolish );
DECLARE_DO_FUN( do_map );
DECLARE_DO_FUN( do_securit );
DECLARE_DO_FUN( do_security );
DECLARE_DO_FUN( do_demolis );
DECLARE_DO_FUN( do_repop );
DECLARE_DO_FUN( do_closeexit );
DECLARE_DO_FUN( do_history );
DECLARE_DO_FUN( do_chunk );
DECLARE_DO_FUN( do_pit );
DECLARE_DO_FUN( do_install );
DECLARE_DO_FUN( do_winstall );
DECLARE_DO_FUN( do_sdelete );
DECLARE_DO_FUN( do_return );
DECLARE_DO_FUN( do_smite );
DECLARE_DO_FUN( do_reward );
DECLARE_DO_FUN( do_recho );
DECLARE_DO_FUN( do_shoot );
DECLARE_DO_FUN( do_mmake );
DECLARE_DO_FUN( do_identify );
DECLARE_DO_FUN( do_backup );
DECLARE_DO_FUN( do_bmake );
DECLARE_DO_FUN( do_objclear );
DECLARE_DO_FUN( do_swap );
DECLARE_DO_FUN( do_teleport );
DECLARE_DO_FUN( do_talktodesc );
DECLARE_DO_FUN( do_allow );
DECLARE_DO_FUN( do_history );
DECLARE_DO_FUN( do_test );
DECLARE_DO_FUN( do_deletefromscores );
DECLARE_DO_FUN( do_stats );
DECLARE_DO_FUN( do_implant );
DECLARE_DO_FUN( do_mset );
DECLARE_DO_FUN( do_darts );
DECLARE_DO_FUN( do_buildingreimburse );
DECLARE_DO_FUN( do_mstat );
DECLARE_DO_FUN( do_qpspend );
DECLARE_DO_FUN( do_oarmortype );
DECLARE_DO_FUN( do_sedit );
DECLARE_DO_FUN( do_doom );
DECLARE_DO_FUN( do_generate );
DECLARE_DO_FUN( do_research );
DECLARE_DO_FUN( do_sneak );
DECLARE_DO_FUN( do_repair );
DECLARE_DO_FUN( do_destroy );
DECLARE_DO_FUN( do_refine );
DECLARE_DO_FUN( do_sell );
DECLARE_DO_FUN( do_skills );
DECLARE_DO_FUN( do_chemistry );
DECLARE_DO_FUN( do_dig );
DECLARE_DO_FUN( do_target );
DECLARE_DO_FUN( do_accept );
DECLARE_DO_FUN( do_aban );
DECLARE_DO_FUN( do_alliances );
DECLARE_DO_FUN( do_leave );
DECLARE_DO_FUN( do_setalliance );
DECLARE_DO_FUN( do_amem );
DECLARE_DO_FUN( do_practice );
DECLARE_DO_FUN( do_kick );
DECLARE_DO_FUN( do_punch );
DECLARE_DO_FUN( do_bload );
DECLARE_DO_FUN( do_findalts );
DECLARE_DO_FUN( do_tunnel );
DECLARE_DO_FUN( do_home );
DECLARE_DO_FUN( do_move );
DECLARE_DO_FUN( do_connect );
DECLARE_DO_FUN( do_computer );
DECLARE_DO_FUN( do_classes );
DECLARE_DO_FUN( do_status );
DECLARE_DO_FUN( do_trade );
DECLARE_DO_FUN( do_boom );
DECLARE_DO_FUN( do_awhere );
DECLARE_DO_FUN( do_track );
DECLARE_DO_FUN( do_exresearch );
DECLARE_DO_FUN( do_paintball );
DECLARE_DO_FUN( do_where );
DECLARE_DO_FUN( do_createalliance );
DECLARE_DO_FUN( do_setowner );
DECLARE_DO_FUN( do_message );
DECLARE_DO_FUN( do_spy );
DECLARE_DO_FUN( do_radiosilence );
DECLARE_DO_FUN( do_torment );
DECLARE_DO_FUN( do_locate );
DECLARE_DO_FUN( do_update_website );
DECLARE_DO_FUN( do_paradrop );
DECLARE_DO_FUN( do_savemap );
DECLARE_DO_FUN( do_construct );
DECLARE_DO_FUN( do_reset );
DECLARE_DO_FUN( do_asshole );
DECLARE_DO_FUN( do_clean );
DECLARE_DO_FUN( do_sblast );
DECLARE_DO_FUN( do_psy_message );
DECLARE_DO_FUN( do_nuke );
DECLARE_DO_FUN( do_loadlist );
DECLARE_DO_FUN( do_sresearch );
DECLARE_DO_FUN( construct_space_vessal );
DECLARE_DO_FUN( construct_alien_vessal );
DECLARE_DO_FUN( do_lift );
DECLARE_DO_FUN( do_land );
DECLARE_DO_FUN( space_warp );
DECLARE_DO_FUN( space_mine );
DECLARE_DO_FUN( do_info );
DECLARE_DO_FUN( do_teleport_b );
DECLARE_DO_FUN( do_mimic );
DECLARE_DO_FUN( do_deathray );
DECLARE_DO_FUN( do_backup_building );
DECLARE_DO_FUN( do_mspend );
DECLARE_DO_FUN( do_formulas );
DECLARE_DO_FUN( do_meda );
DECLARE_DO_FUN( do_medal );
DECLARE_DO_FUN( do_search );
DECLARE_DO_FUN( do_loadfake );
DECLARE_DO_FUN( do_vinstall );
DECLARE_DO_FUN( do_battlestations );
DECLARE_DO_FUN( do_stop );
DECLARE_DO_FUN( do_queue );
DECLARE_DO_FUN( do_spacepop );
DECLARE_DO_FUN( do_run );
DECLARE_DO_FUN( do_proficiencies );
DECLARE_DO_FUN( do_fix );
DECLARE_DO_FUN( do_engineer );
DECLARE_DO_FUN( do_space_move );
DECLARE_DO_FUN( do_space_hijack );
DECLARE_DO_FUN( do_paintlock );
DECLARE_DO_FUN( do_nukem );
DECLARE_DO_FUN( do_cloneflag );
DECLARE_DO_FUN( do_shell );
DECLARE_DO_FUN( do_blindupdate );
DECLARE_DO_FUN( do_prize );
DECLARE_DO_FUN( do_donate );
DECLARE_DO_FUN( do_oresearch );
DECLARE_DO_FUN( do_multiplayers );
DECLARE_DO_FUN( do_peek );
DECLARE_DO_FUN( do_use );
DECLARE_DO_FUN( do_setexit );
DECLARE_DO_FUN( do_mute );
DECLARE_DO_FUN( do_coords );
DECLARE_DO_FUN( do_settunnel );
DECLARE_DO_FUN(do_buildings);
DECLARE_DO_FUN( do_ammo );
DECLARE_DO_FUN( do_vehicle_status );
DECLARE_DO_FUN( do_peace );
DECLARE_DO_FUN( do_list );
DECLARE_DO_FUN( do_qpmode );
DECLARE_DO_FUN( do_train );
DECLARE_DO_FUN( do_xpreward );
DECLARE_DO_FUN( do_xpmode );
DECLARE_DO_FUN( do_gunner_shoot );
DECLARE_DO_FUN( do_scanmap );
DECLARE_DO_FUN( do_owhereflag );
DECLARE_DO_FUN( do_gpreward );
DECLARE_DO_FUN( do_bye          );
DECLARE_DO_FUN( do_pager );
DECLARE_DO_FUN( do_bscan );
DECLARE_DO_FUN( do_imminfo );
DECLARE_DO_FUN( do_changes );
DECLARE_DO_FUN( do_logs );
DECLARE_DO_FUN( do_addchange            );
DECLARE_DO_FUN( do_chedit               );
DECLARE_DO_FUN( do_immlog );
DECLARE_DO_FUN( do_phase );
DECLARE_DO_FUN( do_survey );
DECLARE_DO_FUN( do_vset );
DECLARE_DO_FUN( do_ammolist );
DECLARE_DO_FUN( do_bomb );
DECLARE_DO_FUN( do_devastate );
DECLARE_DO_FUN( do_rules );
DECLARE_DO_FUN( do_ranks );
DECLARE_DO_FUN( do_rangen );


#undef  CD
#undef  MID
#undef  OD
#undef  OID
#undef  RID
#undef  SF
#undef  OF
