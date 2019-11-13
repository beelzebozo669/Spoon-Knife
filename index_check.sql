set pages 9999
set lines 77
set trimspool on
clear col
clear breaks
set heading on
set feedback off
set verify off
set echo off

column dns heading "Density"         format 999
column ebl heading "Extra Blocks"    format 999,999,999
column nam heading "Name"            format A30
column own heading "Owner"           format A15

select /*+ ordered */   
       u.name own, 
       o.name nam,
       (100*i.rowcnt*(sum(h.avgcln)+11)) /
         (i.leafcnt * (p.value-66-i.initrans*24)  ) dns,
       floor((1-i.pctfree$/100)*i.leafcnt-i.rowcnt*(sum(h.avgcln)+11) /
         (p.value-66-i.initrans*24)  ) ebl
from sys.ind$  i,  sys.icol$  ic,  sys.hist_head$  h,
     (select ksppstvl  value
      from sys.x$ksppi x, sys.x$ksppcv y 
      where x.indx = y.indx 
      and ksppinm = 'db_block_size') p,
     sys.obj$  o,  sys.user$  u
where i.leafcnt > 1
  and i.type# in (1,4,6) 
  and ic.obj# = i.obj# 
  and h.obj# = i.bo# 
  and h.intcol# = ic.intcol# 
  and o.obj# = i.obj# 
  and o.owner# != 0 
  and u.user# = o.owner#
group by u.name,o.name,i.rowcnt,i.leafcnt,i.initrans,i.pctfree$,p.value
having  50*i.rowcnt*(sum(h.avgcln) + 11) < 
       (i.leafcnt*(p.value-66-i.initrans*24))*(50-i.pctfree$) 
   and floor((1 - i.pctfree$/100)*i.leafcnt-i.rowcnt*(sum(h.avgcln) + 11) / 
            (p.value-66-i.initrans*24) ) > 0
order by 4 desc, 3
/
