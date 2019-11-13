===================================================================================================
-- 27388 users in slc_employees with active_flag = 'N' and 'Y'
  SELECT count(class_user_id)
    FROM class.slc_employees;
===================================================================================================
-- 24360 users in slc_employees with active_flag = 'N'
  SELECT count(class_user_id)
    FROM class.slc_employees
   WHERE active_flag = 'N';
===================================================================================================
-- 3028 users in slc_employees with active_flag = 'Y'
   SELECT count(class_user_id)
    FROM class.slc_employees
   WHERE active_flag = 'Y';
===================================================================================================
-- 2578
  SELECT count(username)
    FROM dba_users;
===================================================================================================
-- 82 users in dba_users and in slc_employees with active_flag = 'N'
  SELECT class_user_id, forenames, surname, TO_CHAR(created_date,'DD/MM/YYYY HH24:MI:SS') when
    FROM class.slc_employees
   WHERE class_user_id IN (
                             SELECT username
                               FROM dba_users
                              WHERE username IN (
                                                   SELECT class_user_id
                                                     FROM class.slc_employees
                                                    WHERE active_flag = 'N'
                                                )
                          )
     AND class_user_id NOT IN ('BATCHPRO','CLASS','DEVELOP1')
ORDER BY TO_CHAR(created_date,'YYYY/MM/DD HH24:MI:SS');
===================================================================================================
-- 2390 uses in dba_users and in slc_employees with active_flag = 'Y'
  SELECT class_user_id, forenames, surname, TO_CHAR(created_date,'DD/MM/YYYY HH24:MI:SS') when
    FROM class.slc_employees
   WHERE class_user_id IN (
                             SELECT username
                               FROM dba_users
                              WHERE username IN (
                                                   SELECT class_user_id
                                                     FROM class.slc_employees
                                                    WHERE active_flag = 'Y'
                                                )
                          )
     AND class_user_id NOT IN ('BATCHPRO','CLASS','DEVELOP1')
ORDER BY TO_CHAR(created_date,'YYYY/MM/DD HH24:MI:SS');
===================================================================================================
-- 70 users
  SELECT username
    FROM dba_users
   WHERE account_status = 'OPEN'
     AND username NOT IN (
'ALPHA',
'BATCH_RPT',
'CDCADMIN',
'CLASS',
'CLASS_RPT',
'DBSNMP',
'DEBTSALE',
'DEVELOP1',
'DRSYS',
'GB_CLASSFMINV05',
'GB_CLASSREINV',
'GB_CLASSREL',
'GB_CLASSRELADV',
'GB_CLASSRESUP',
'GB_CLASSRINV',
'GB_CLASSRINV01',
'GB_CLASSRINV02',
'GB_CLASSRINV03',
'GB_CLASSRINV04',
'GB_CLASSRINV05',
'GB_CLASSRSUP',
'GB_CLASSRSUP02',
'GB_CLASSRSUP03',
'GB_CLASSRSUP04',
'GB_CLASSRSUP05',
'GB_CLASSRSUP06',
'GB_CLASSRSUP07',
'GB_CLASSRSUP08',
'GB_CLASSRSUP09',
'GCJOB',
'LSS',
'LSSREAD',
'MICROSTRAT_RO',
'MS_DSAR',
'OAI',
'OAI_STAGE',
'ORACLE',
'ORDS_PUBLIC_USER',
'PATROL',
'POPUL',
'PROTOREAD',
'QAS',
'SAVREADONLY',
'SRVB_ACCBCP',
'SRVB_ACCREC',
'SVC_JDBC_SAILPOINT_CLASS_PE01',
'SYS',
'SYSDG',
'SYSTEM',
'TOAD',
'WAREHOUSE',
'WEBUTIL',
'XXAQ',
'XXFV',
'XXOLTPCST',
'XXOLTPCUS',
'XXOLTPDRPAY',
'XXOLTPHEI',
'XXOLTPLEA',
'XXOLTPOPT',
'XXOLTPREP',
'XXOLTPUALL',
'XXOP',
'XXPREPAY',
'XXSL')
MINUS
  SELECT class_user_id
    FROM class.slc_employees
   WHERE active_flag = 'Y';
===================================================================================================
CLASS databases are separated both by database name and unix server
Dev(Performance Testing)	-	CLASS_X1	-	d1avdbcspp23.slc.internal
Dev							-	CL12CDEV	-	d2avdbcsde15.slc.devuat
Dev							-	SYS97		-	d2avdbcsde20.slc.devuat
NextTest					-	CL12CNT		-	d2avdbcste12.slc.devuat
SupportTest					-	CL12CST		-	d1avdbcspp21.slc.internal
BothwellSt	(UAT)			-	CL12CBS		-	d1avdbcste17.slc.internal
Production					-	CLASS_L		-	d2avdbcspe10.slc.internal
===================================================================================================
3028 class_user_id in SLC_EMPLOYEES	where ACTIVE_FLAG = 'Y'
2578 users in DBA_USERS	
====
 491
 
-- 610 class_user_id where it IS NULL in SLC_EMPLOYEES with no corresponding entry in DBA_USERS
  SELECT class_user_id, active_flag, forenames, surname
    FROM class.slc_employees
   WHERE class_user_id IS NULL
ORDER BY active_flag, surname, forenames

==================================================================================================

-- 638 class_user_id where class_user_id and does not exist in DBA_USERS
   SELECT class_user_id
    FROM class.slc_employees
   WHERE active_flag = 'Y'
     AND class_user_id NOT IN (
                                 SELECT username
                                   FROM dba_users
                              )
MINUS
  SELECT username
    FROM dba_users;

==================================================================================================
--- user.sql

CLEAR SCREEN

SET LINESIZE 200
SET PAGESIZE 25
SET VERIFY OFF

ACCEPT uid CHAR PROMPT 'Enter user name to be queried : '

COLUMN forenames      FORMAT A30 HEADING "Forename"
COLUMN surname        FORMAT A30 HEADING "Surname"
COLUMN class_user_id  FORMAT A15 HEADING "Class User ID"
COLUMN created_by     FORMAT A15 HEADING "Created By"
COLUMN created        FORMAT A20 HEADING "Created"
COLUMN username       FORMAT A30 HEADING "User name"
COLUMN active_flag    FORMAT A30 HEADING "Active Flag"
COLUMN login          FORMAT A20 HEADING "Login Date"
COLUMN account_status FORMAT A30 HEADING "Status"
COLUMN locked         FORMAT A20 HEADING "Locked"
COLUMN expired        FORMAT A20 HEADING "Expired"
COLUMN created        FORMAT A20 HEADING "Created"
COLUMN grantee        FORMAT A30 HEADING "Grantee"
COLUMN granted_role   FORMAT A30 HEADING "Granted Role(s)"

ttitle center 'SLC EMPLOYEE Query Results' SKIP 2

  SELECT forenames,
         surname,
         class_user_id,
         active_flag,
         created_by,
         TO_CHAR(created_date,'DD/MM/YYYY HH24:MI:SS') created
    FROM class.slc_employees
   WHERE class_user_id IN UPPER('&uid')
ORDER BY active_flag, class_user_id;

alter session set nls_date_format = 'DD/MM/YYYY';

ttitle center 'Logon Audit Query Results' SKIP 2

  SELECT username, to_char(max(timestamp),'DD/MM/YYYY HH24:MI:SS') LOGIN
    FROM logon_audit
   WHERE username IN UPPER('&uid')
GROUP BY username
ORDER BY 2, 1;

ttitle center 'DBA Users Query Results' SKIP 2

  SELECT username,
         account_status,
         TO_CHAR(lock_date,'DD/MM/YYYY HH24:MI:SS') locked,
         TO_CHAR(expiry_date,'DD/MM/YYYY HH24:MI:SS') expired,
         TO_CHAR(created,'DD/MM/YYYY HH24:MI:SS') created
    FROM dba_users
   WHERE username IN UPPER('&uid')
ORDER BY username;

ttitle center 'User Privileges Query Results' SKIP 2

  SELECT *
    FROM dba_role_privs
   WHERE grantee IN UPPER('&uid')
ORDER BY grantee, granted_role;

SET LINESIZE 80
SET PAGESIZE 20

UNDEFINE uid
TTITLE OFF
CLEAR COLUMNS
SET VERIFY ON
==================================================================================================
--- profile.sql

CLEAR SCREEN

SET LINESIZE 100
SET PAGESIZE 30

COLUMN profile     FORMAT A30   HEADING "Profile Name"
COLUMN profile_ddl FORMAT A60   HEADING "Profile DDL"

SET VERIFY ON
TTITLE CENTER 'List Profiles' SKIP 2
SET VERIFY OFF

   SELECT DISTINCT profile
     FROM dba_profiles
ORDER BY profile;

CLEAR COLUMNS

ACCEPT profile CHAR PROMPT 'Enter profile to be queried : '

SET LONG 90000 LONGCHUNKSIZE 90000 PAGESIZE 0 LINESIZE 1000 FEEDBACK OFF VERIFY OFF TRIMSPOOL ON
COLUMN ddl         FORMAT A1000 HEADING "DDL"

BEGIN
   DBMS_METADATA.SET_TRANSFORM_PARAM (DBMS_METADATA.SESSION_TRANSFORM, 'SQLTERMINATOR', TRUE);
   DBMS_METADATA.SET_TRANSFORM_PARAM (DBMS_METADATA.SESSION_TRANSFORM, 'PRETTY', TRUE);
END;
/

TTITLE CENTER 'Profile DDL' SKIP 2

  SELECT DBMS_METADATA.GET_DDL('PROFILE', profile) AS profile_ddl
    FROM (
            SELECT DISTINCT profile
              FROM dba_profiles
         )
   WHERE profile LIKE UPPER('&profile');

ACCEPT function CHAR PROMPT 'Enter function to be queried : '

COLUMN function_ddl FORMAT A1000 HEADING "Profile DDL"

TTITLE CENTER 'Function DDL' SKIP 2

  SELECT DBMS_METADATA.GET_DDL('FUNCTION','&function') function_ddl
    FROM dual;

SET LINESIZE 80 PAGESIZE 14 FEEDBACK ON VERIFY ON
UNDEFINE profile
CLEAR COLUMNS

==================================================================================================
	
	
	
	

	
EXPIRED                  --- 62
EXPIRED & LOCKED         --- 0
EXPIRED & LOCKED(TIMED)  --- 1
EXPIRED(GRACE)           --- 57
LOCKED                   --- 18
LOCKED(TIMED)            --- 47
OPEN                     --- 2290

3028
2475
====
 553
 
 
3069 -- slc_employees - Y
2390 -- slc_employees - Y and dba_usersed

====
 679

2578 -- dba_users
2390 -- slc_employees - Y
====
 188