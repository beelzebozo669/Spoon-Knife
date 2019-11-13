create or replace package sappk231
as

  /**
   * <a name="package_summary"></a><a name="field_detail"></a><a name="type_detail"></a><a name="package_detail"></a>
   * <table width="100%" cellspacing="0" cellpadding="3" border="1">
   * <tr class="TableHeadingColor">
   * <td colspan="1"><font size="+2"><b>Package  sappk231</b></font></td>
   * </tr>
   * </table>
   *
   * <b>Project:</b> Customer Involvement Types<br/>
   * <b>Description:</b> List of a Customer's Involvement Types<br/>
   * <b>Author:</b> Phil Goldsbrough<br/>
   * <b>Copyright(c):</b> 2009 The Student Loan Company Ltd., Glasgow, UK<br/>
   * <b>Product:</b> PL/SQL <br/>
   * <b>Commit inside:</b> No<br/>
   * <b>Rollback inside:</b> No<br/>
   * <b>Webservice:</b> CustInvolveTypesWS<br/>
   * @headcom
  */

  /**
   * Ref Cursor to return a list of a Customer's Involvements with the SLC sorted by Academic Year descending.
   * <p>
   * Consists of the following data items:
   * <ul>
   * <li>csr_type_code  From Domain XXCO_CUSTOMER_TYPE</li>
   * <li>csr_type_abbrev  From Domain XXCO_CUSTOMER_TYPE</li>
   * <li>csr_type_desc  From Domain XXCO_CUSTOMER_TYPE</li>
   * <li>academic_year  Academic Year of the involvements</li>
   * <li>work_stage_id  Current Work Stage ID</li>
   * <li>work_stage_desc  Description of Current Work Stage</li>
   * </ul>
   */

  type rc_customer_involvements is ref cursor;
  
  /**
   * Customer Involvement Types.
   * <p>
   * List of a Customer's Involvements with the SLC sorted by Academic Year descending.
   * <p>
   * <br><b>DB impact:</B><br/>
   * <table border="1">
   * <tr>
   * <th>Activity</th>
   * <th>Object Type</th>
   * <th>Object Name</th>
   * </tr>
   * <tr>
   * <td><b>C</b></td>
   * <td>None</td>
   * <td>None</td>
   * </tr>
   * <tr>
   * <td><b>R</b></td>
   * <td>XXSL_ASSESSMENT_HISTORIES<br/>
   *     XXSL_REF_CODES<br/>
   *     XXSL_SUPPORT_APPPLICATIONS<br/>
   *     XXSL_SUPPORT_ASSESSMENTS<br/>
   *     XXSL_WORK_STAGE_TYPES</td>
   * <td>None</td>
   * <tr>
   * <td><b>U</b></td>
   * <td>None</td>
   * <td>None</td>
   * </tr>
   * <tr>
   * <td><b>D</b></td>
   * <td>None</td>
   * <td>None</td>
   * </tr>
   * </table>
   * <br><b>Subroutine(s)</b><br/>
   * helpk002.p_initialise<br/>
   * helpk002.p_set_routine<br/>
   * helpk002.p_add_message_item<br/>
   * helpk002.f_raise_message<br/>
   * helpk002.p_exit_routine<br/>
   * @param p_customer_id  ID of the Customer
   * @param p_csr_involvements  Ref Cursor to return the involvement types
   * @param p_error_code  Error code returned
   * <ul>
   * <li>-1 Technical failure</li> 
   * <li>0 Success</li>
   * </ul>
   * @param p_error_message  Descriptive error message
   */

  procedure p_customer_involvement_types ( p_customer_id       in  xxsl_customers.id%type,
                                           p_csr_involvements  out rc_customer_involvements,
                                           p_error_code        out number,
                                           p_error_message     out varchar2 );

end sappk231;
/

create or replace package body sappk231
as
  --
  -- Define global package variables
  --
  g_module       constant char(13)     := 'sappk231' ;
  g_log_context  constant varchar2(50) := 'Customer Involvement Type';

  --
  -- define custom exceptions
  --
  e_routine  exception;  -- exceptions raised internally within a routine

  procedure p_customer_involvement_types ( p_customer_id       in  xxsl_customers.id%type,
                                           p_csr_involvements  out rc_customer_involvements,
                                           p_error_code        out number,
                                           p_error_message     out varchar2 )
  is

    l_error_code  number := 0;
    l_messages    varchar2(4000);  -- definition based on helpk002.g_default_message

  begin

    helpk002.p_initialise ( p_context => g_log_context );
    helpk002.p_set_routine ( p_package => g_module,
                             p_routine => 'p_customer_involvement_types' );
                             
    --
    -- intitialise out parameters especially collections
    --
    p_error_code := l_error_code;
    p_error_message := substr ( l_messages, 1, 256);

    open p_csr_involvements
    for
      select '91'                          as csr_type_code,
             'Priority CurrentYr Income'   as csr_type_abbrev,
             'Priority CurrentYr Income'   as csr_type_desc,
             null                          as academic_year,
             null                          as work_stage_id,
             ''                            as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap,
             xxsl_sponsor_fin_statements sfs
      where  sap.csr_id = p_customer_id
      and    SFS.CSR_ID = sap.csr_id
      and    sap.id = sas.sap_id
      and    sfs.acy_id = sfs.fny_id
      union
      select '92'                          as csr_type_code,
             'Priority NHS Course'         as csr_type_abbrev,
             'Priority NHS Course'         as csr_type_desc,
             null                          as academic_year,
             null                          as work_stage_id,
             ''                            as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap
      where  sap.csr_id = p_customer_id
      and    sap.id = sas.sap_id
      and  ( SAS.nhs_bursary_ind = 'Y'
          or SAS.nhs_bursary_ind_crs = 'Y'
          or SAS.NON_INCOME_ASS_NHS_BURS_FLAG = 'Y'
          or SAS.APPLIED_FOR_NHS_DOH_GRANT_FLAG = 'Y')
      union
      select '93'                          as csr_type_code,
             'Priority Sponsor Income Var' as csr_type_abbrev,
             'Priority Sponsor Income Var' as csr_type_desc,
             null                          as academic_year,
             null                          as work_stage_id,
             ''                            as work_stage_desc
      from   xxsl_sponsor_fin_statements sfs,
             xxsl_support_assessments    sas,
             xxsl_support_applications   sap
      where  sap.csr_id = p_customer_id
      and    sfs.csr_id = sap.csr_id
      and    sap.id = sas.sap_id
      and  ( SFS.hmrc_exception_reported_ind = 'Y'
          or SFS.hmrc_resolved_ind = 'Y' )
      union
      select '94'                        as csr_type_code,
             'Priority Study Abroad'     as csr_type_abbrev,
             'Priority Study Abroad'     as csr_type_desc,
             null                        as academic_year,
             null                        as work_stage_id,
             ''                          as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap
      where  sap.csr_id = p_customer_id
      and    sap.id = sas.sap_id
      and  ( SAS.MAJORITY_STUDY_ABROAD_FLAG = 'Y'
          or SAS.ABROAD_PLACEMENT_FLAG = 'Y'
          or SAS.ABROAD_PAID_PLACEMENT_FLAG = 'Y')
      union
      select '95'                        as csr_type_code,
             'Priority Prev Study'       as csr_type_abbrev,
             'Priority Prev Study'       as csr_type_desc,
             null                        as academic_year,
             null                        as work_stage_id,
             ''                          as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap,
             xxsl_previous_study_summaries pss
      where  sap.csr_id = p_customer_id
      and    pss.sap_id = sap.id
      and    sap.id = sas.sap_id
      union
      select '96'                                       as csr_type_code,
             to_char(SAS.COURSE_START_DATE,'YYYYMMDD')  as csr_type_abbrev,
             'Priority CCG'                             as csr_type_desc,
             null                                       as academic_year,
             null                                       as work_stage_id,
             ''                                         as work_stage_desc
      from   xxsl_ccare_app_child_estimates cce,
             xxsl_support_assessments       sas,
             xxsl_support_applications      sap
      where  sap.csr_id = p_customer_id
      and    cce.sap_id = sap.id
      and    sap.id = sas.sap_id
      and   (  CCE.BEFORE_TERM1_COSTS  
             + CCE.TERM1_COSTS  
             + CCE.XMAS_VACATION_COSTS  
             + CCE.TERM2_COSTS  
             + CCE.EASTER_VACATION_COSTS  
             + CCE.TERM3_COSTS  
             + CCE.SUMMER_VACATION_COSTS  ) > 0
      union
      select '97'                        as csr_type_code,
             'Priority FT'               as csr_type_abbrev,
             'Priority FT'               as csr_type_desc,
             null                        as academic_year,
             null                        as work_stage_id,
             ''                          as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap
      where  sap.csr_id = p_customer_id
      and    sap.id = sas.sap_id
      and    SAS.RELATIVE_FROM_EEA_FLAG = 'Y'
      union
      select '98'                        as csr_type_code,
             'Priority PT'               as csr_type_abbrev,
             'Priority PT'               as csr_type_desc,
             null                        as academic_year,
             null                        as work_stage_id,
             ''                          as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap
      where  sap.csr_id = p_customer_id
      and    sap.id = sas.sap_id
      and    SAS.RELATIVE_FRM_EEU_WRK_UK_FLAG = 'Y'
      union
      select '99'                        as csr_type_code,
             'Priority'                  as csr_type_abbrev,
             'Priority'                  as csr_type_desc,
             null                        as academic_year,
             null                        as work_stage_id,
             ''                          as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap
      where  sap.csr_id = p_customer_id
      and    sap.id = sas.sap_id
      and   (sas.swiss_parent_in_uk_ind ='Y'
         and sas.child_of_swiss_national_ind = 'Y')
      union
      select distinct
             xrc.rv_low_value      as csr_type_code,
             xrc.rv_abbreviation   as csr_type_abbrev,
             xrc.rv_meaning        as csr_type_desc,
             null                  as academic_year,
             null                  as work_stage_id,
             ''                    as work_stage_desc
      from   xxsl_support_applications sap,
             xxsl_ref_codes            xrc
      where  sap.csr_id = p_customer_id
      and    sap.current_wst_id not in (13,14,21)
      and    sap.lea_id not in ('C-01','EM01','EM02')
      and    xrc.rv_domain = 'XXCO_CUSTOMER_TYPE'
      and    xrc.rv_abbreviation = 'HE_STU'
      union
      select distinct
             xrc.rv_low_value      as csr_type_code,
             xrc.rv_abbreviation   as csr_type_abbrev,
             xrc.rv_meaning        as csr_type_desc,
             null                  as academic_year,
             null                  as work_stage_id,
             ''                    as work_stage_desc
      from   xxsl_support_applications sap,
             xxsl_ref_codes            xrc
      where  sap.csr_id = p_customer_id
      and    sap.current_wst_id not in (13,14,21)
      and    sap.lea_id = 'C-01'
      and    xrc.rv_domain = 'XXCO_CUSTOMER_TYPE'
      and    xrc.rv_abbreviation = 'EU'
      union
      select distinct
             xrc.rv_low_value      as csr_type_code,
             xrc.rv_abbreviation   as csr_type_abbrev,
             xrc.rv_meaning        as csr_type_desc,
             null                  as academic_year,
             null                  as work_stage_id,
             ''                    as work_stage_desc
      from   xxsl_support_assessments  sas,
             xxsl_support_applications sap,
             xxsl_ref_codes            xrc
      where  ( sas.sponsor1_csr_id = p_customer_id or
               sas.sponsor2_csr_id = p_customer_id )
      and    sap.id = sas.sap_id
      and    xrc.rv_domain = 'XXCO_CUSTOMER_TYPE'
      and    xrc.rv_abbreviation = 'HE_SPO'
      union
      select distinct
             xrc.rv_low_value      as csr_type_code,
             xrc.rv_abbreviation   as csr_type_abbrev,
             xrc.rv_meaning        as csr_type_desc,
             null                  as academic_year,
             null                  as work_stage_id,
             ''                    as work_stage_desc
      from   xxsl_assessment_histories ash,
             xxsl_support_applications sap,
             xxsl_ref_codes            xrc
      where  ( ash.sponsor1_csr_id = p_customer_id or
               ash.sponsor2_csr_id = p_customer_id )
      and    sap.id = ash.sap_id
      and    xrc.rv_domain = 'XXCO_CUSTOMER_TYPE'
      and    xrc.rv_abbreviation = 'HE_SPO';
      
    --
    -- Assign Out variables
    --
    p_error_code := l_error_code;
    p_error_message := substr ( l_messages, 1, 256);

    --
    -- exit the routine
    --
    helpk002.p_exit_routine;

  exception

    when others
    then
      helpk002.p_add_message_item ( p_message => l_messages,
                                    p_item => sqlcode || ': ' || sqlerrm );
                                    
      l_messages := helpk002.f_raise_message ( p_type => helpk002.g_business_event,
                                               p_level => helpk002.g_level_error,
                                               p_message => l_messages );
                                               
      p_error_code := -1;
      p_error_message := substr ( l_messages, 1, 256 );
      helpk002.p_exit_routine;

  end p_customer_involvement_types;

end sappk231;
/