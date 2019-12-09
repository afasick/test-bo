<?php
 /*********************************************************************************
 *          Filename: MembersGrid.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "MembersGrid.php";



check_security(2);


?><html>
<head>
<title>Book Store</title>
<meta name="GENERATOR" content="YesSoftware CodeCharge v.1.1.19 using 'PHP.ccp'">
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="expires" content="0"> 
<meta http-equiv="cache-control" content="no-cache">
</head>
<body style="background-color: #FFFFFF; color: #000000; font-family: Arial, Tahoma, Verdana, Helveticabackground-color: #FFFFFF; color: #000000; font-family: Arial, Tahoma, Verdana, Helvetica">
<center>
 <table>
  <tr>
   <td valign="top">
 <? Menu_Show() ?>
   
   </td>
  </tr>
 </table>
</center>
<hr>
 <table>
  <tr>
   
   <td valign="top"><font face=arial size=2> Enter full or partial login, first or last name</font>
<? Search_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Members_Show() ?>
    
   </td>
  </tr>
 </table>

<center>
<hr size=1 width=60%>
 <table>
  <tr>
   <td valign="top">
<? Footer_Show() ?>
    </td>
   
  </tr>
 </table>
 
<center><font face="Arial"><small>This dynamic site was generated with <a href="http://www.codecharge.com">CodeCharge</a></small></font></center>
</body>
</html>
<? 



//********************************************************************************



function Search_Show()
{
  global $styles;
  
  $action_page = "MembersGrid.php";

  


    $fldname = strip(get_param("name"));
  ?>
    <form method="GET" action="<?= $action_page ?>">
    <table style="">
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Name</font></td>
      <td style="background-color: #FFFFFF; border-width: 1">
         <input type="text" name="name" maxlength="10" value="<?= tohtml($fldname) ?>" size="10" ></td>
     <td ><input type="submit" value="Search">
     </td>     
    </tr>
     
   </table>
   </form>
<?
  
}

function Members_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sMembersErr; //-- error string

  
  //-- transit parameters
  $transit_params = "name=" . tourl(strip(get_param("name"))) . "&";
  //-- form parameters
  $form_params = "name=" . tourl(get_param("name")) . "&name=" . tourl(get_param("name")) . "&name=" . tourl(get_param("name")) . "&";//-- SQL for order field
  $sOrder = " order by m.member_login Asc";

  $HasParam = false;

  $iSort = get_param("FormMembers_Sorting");
  $iSorted = get_param("FormMembers_Sorted");

  //-- process sort commands
  $sDirection = "";
  $sSortParams = "";
  if($iSort)
  {
    if($iSort == $iSorted)
    {
      $form_sorting = "";
      $sDirection = " DESC";
      $sSortParams = "FormMembers_Sorting=" . $iSort . "&FormMembers_Sorted=" . $iSort . "&";
    }
    else
    {
      $form_sorting = $iSort;
      $sDirection = " ASC";
      $sSortParams = "FormMembers_Sorting=" . $iSort . "&FormMembers_Sorted=" . "&";
    }
    
    if ($iSort == 1) $sOrder = " order by m.member_login" . $sDirection;
    if ($iSort == 2) $sOrder = " order by m.first_name" . $sDirection;
    if ($iSort == 3) $sOrder = " order by m.last_name" . $sDirection;
    if ($iSort == 4) $sOrder = " order by m.member_level" . $sDirection;
    if (!strlen($sOrder))  $sDirection = "";
  }
  

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="4"><a name="Members"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Members</font></a></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormMembers_Sorting=1&FormMembers_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Login</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormMembers_Sorting=2&FormMembers_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">First Name</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormMembers_Sorting=3&FormMembers_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Last Name</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormMembers_Sorting=4&FormMembers_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Level</font></a></td>
      </tr>
<?

  $sWhere = "";
  
    //-- Check Members parameter and create a valid sql for where clause
  
  $pname = get_param("name");
  if(strlen($pname))
  {
    $HasParam = true;
    $sWhere = "m.member_login like " . tosql("%".$pname . "%","Text") . " or " . "m.first_name like " . tosql("%".$pname . "%","Text") . " or " . "m.last_name like " . tosql("%".$pname . "%","Text");
  }
  
  //-- populate arrays for list of values
  $lov_member_level = get_lov_values("1;Member;2;Administrator");
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " WHERE (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "select m.first_name as m_first_name, " . 
    "m.last_name as m_last_name, " . 
    "m.member_id as m_member_id, " . 
    "m.member_level as m_member_level, " . 
    "m.member_login as m_member_login " . 
    " from members m ";
  
  $sSQL = $sSQL . $sWhere . $sOrder;

  //-- insert button
  $form_action = "MembersRecord.php";
  //-- variables of the page scroller
  $iPage = get_param("FormMembers_Page");
  if(!strlen($iPage)) $iPage = 1;
  $RecordsPerPage = 20;

  //-- do SQL query
  $db->query($sSQL);
  
  //-- move through the recordset - as scroller requires
  $position_to_seek = ($iPage - 1)*$RecordsPerPage;
  if ($position_to_seek) $db->seek($position_to_seek);
  $iCounter = 0;
  $is_next_record=false;

  //-- show records
  if($db->next_record())
  {
    //-- default values
    

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $fldmember_login = $db->f("m_member_login");
      $fldname = $db->f("m_first_name");
      $fldlast_name = $db->f("m_last_name");
      $fldmember_level = $db->f("m_member_level");
    $iCounter++;
      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="MembersInfo.php?member_id=<?= tourl($db->f("m_member_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldmember_login) ?></font></a>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldname)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldlast_name)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?
  $fldmember_level = $lov_member_level[$fldmember_level]; 
 ?><?=tohtml($fldmember_level)?>&nbsp;</font></td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record  && $iCounter < $RecordsPerPage);
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="4" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>
<tr><td colspan="4" style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">
      <a href="<?= $form_action ?>?<?= $transit_params ?>"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Insert</font></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

      </table>
    <?
    return;
  }

 
 //-- last row of the table is for scroller and "insert" link
  ?>
    
      <tr><td colspan="4" style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">
      <a href="<?= $form_action ?>?<?= $transit_params ?>"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Insert</font></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <?
  //-- scroller
  

  if($is_next_record || $iPage != 1)
  {
    //-- previous page 
    if($iPage == 1)
      $scroller_prev = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormMembers_Page=".$prev_page."#Members\">";
    else
    {
      $prev_page = $iPage - 1;
      $scroller_prev = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormMembers_Page=".$prev_page."#Members\">";
    }
    echo  $scroller_prev."<font "."style=\"font-size: 10pt; color: #CE7E00; font-weight: bold\"".">Previous</font>";
    if ($scroller_prev) echo "</a>";

    //-- current page
    echo " [ $iPage ] ";

    //-- next page
    //if($iPage*$RecordsPerPage >= $db->num_rows())
    if (!$is_next_record)
      $scroller_next = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormMembers_Page=".$next_page."#Members\">";
    else
    {
      $next_page = $iPage + 1;
      $scroller_next = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormMembers_Page=".$next_page."#Members\">";
    }
    echo $scroller_next."<font "."style=\"font-size: 10pt; color: #CE7E00; font-weight: bold\"".">Next</font>";
    if ($scroller_next) echo "</a>";
  }

  //-- the end of the last row and the end of the table
  ?>
      </font></td></tr>
    </table>
  <?

 
}

?>