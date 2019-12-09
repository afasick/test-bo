<?php
 /*********************************************************************************
 *          Filename: OrdersGrid.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "OrdersGrid.php";



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
   
   <td valign="top">
<? Search_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Orders_Show() ?>
    
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
  
  $action_page = "OrdersGrid.php";

  


    $flditem_id = strip(get_param("item_id"));
    $fldmember_id = strip(get_param("member_id"));
  ?>
    <form method="GET" action="<?= $action_page ?>">
    <table style="">
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Item</font></td>
      <td style="background-color: #FFFFFF; border-width: 1"><select name="item_id"><?= get_options("select item_id, name from items order by 2",true,false,$flditem_id);?></select></td>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Member</font></td>
      <td style="background-color: #FFFFFF; border-width: 1"><select name="member_id"><?= get_options("select member_id, member_login from members order by 2",true,false,$fldmember_id);?></select></td>
     <td ><input type="submit" value="Search">
     </td>     
    </tr>
     
   </table>
   </form>
<?
  
}

function Orders_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sOrdersErr; //-- error string

  
  //-- transit parameters
  $transit_params = "item_id=" . tourl(strip(get_param("item_id"))) . "&member_id=" . tourl(strip(get_param("member_id"))) . "&";
  //-- form parameters
  $form_params = "item_id=" . tourl(get_param("item_id")) . "&member_id=" . tourl(get_param("member_id")) . "&";//-- SQL for order field
  $sOrder = " order by o.order_id Asc";

  $HasParam = false;

  $iSort = get_param("FormOrders_Sorting");
  $iSorted = get_param("FormOrders_Sorted");

  //-- process sort commands
  $sDirection = "";
  $sSortParams = "";
  if($iSort)
  {
    if($iSort == $iSorted)
    {
      $form_sorting = "";
      $sDirection = " DESC";
      $sSortParams = "FormOrders_Sorting=" . $iSort . "&FormOrders_Sorted=" . $iSort . "&";
    }
    else
    {
      $form_sorting = $iSort;
      $sDirection = " ASC";
      $sSortParams = "FormOrders_Sorting=" . $iSort . "&FormOrders_Sorted=" . "&";
    }
    
    if ($iSort == 1) $sOrder = " order by i.name" . $sDirection;
    if ($iSort == 2) $sOrder = " order by m.member_login" . $sDirection;
    if ($iSort == 3) $sOrder = " order by o.quantity" . $sDirection;
    if (!strlen($sOrder))  $sDirection = "";
  }
  

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="4"><a name="Orders"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Orders</font></a></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a ><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Edit</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormOrders_Sorting=1&FormOrders_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Item</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormOrders_Sorting=2&FormOrders_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Member</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormOrders_Sorting=3&FormOrders_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Quantity</font></a></td>
      </tr>
<?

  $sWhere = "";
  
  //-- Check item_id parameter and create a valid sql for where clause
  
  $pitem_id = get_param("item_id");
  if(is_number($pitem_id) && strlen($pitem_id))
    $pitem_id = round($pitem_id);
  else 
    $pitem_id = "";
  if(strlen($pitem_id)) 
  {
    $HasParam = true;
    $sWhere .= "o.item_id=" . $pitem_id;
  }
  //-- Check member_id parameter and create a valid sql for where clause
  
  $pmember_id = get_param("member_id");
  if(is_number($pmember_id) && strlen($pmember_id))
    $pmember_id = round($pmember_id);
  else 
    $pmember_id = "";
  if(strlen($pmember_id)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "o.member_id=" . $pmember_id;
  }
  //-- populate arrays for list of values
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " AND (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "select o.item_id as o_item_id, " . 
    "o.member_id as o_member_id, " . 
    "o.order_id as o_order_id, " . 
    "o.quantity as o_quantity, " . 
    "i.item_id as i_item_id, " . 
    "i.name as i_name, " . 
    "m.member_id as m_member_id, " . 
    "m.member_login as m_member_login " . 
    " from orders o, items i, members m" . 
    " where i.item_id=o.item_id and m.member_id=o.member_id  ";
  
  $sSQL = $sSQL . $sWhere . $sOrder;

  //-- insert button
  $form_action = "OrdersRecord.php";
  //-- variables of the page scroller
  $iPage = get_param("FormOrders_Page");
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
    $sField1= "Edit";

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $fldorder_id = $db->f("o_order_id");
      $flditem_id = $db->f("i_name");
      $fldmember_id = $db->f("m_member_login");
      $fldquantity = $db->f("o_quantity");
      $fldField1= "Edit";
    $iCounter++;
      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="OrdersRecord.php?order_id=<?= tourl($db->f("o_order_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldField1) ?></font></a>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($flditem_id)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldmember_id)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldquantity)?>&nbsp;</font></td>
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
      $scroller_prev = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormOrders_Page=".$prev_page."#Orders\">";
    else
    {
      $prev_page = $iPage - 1;
      $scroller_prev = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormOrders_Page=".$prev_page."#Orders\">";
    }
    echo  $scroller_prev."<font "."style=\"font-size: 10pt; color: #CE7E00; font-weight: bold\"".">Previous</font>";
    if ($scroller_prev) echo "</a>";

    //-- current page
    echo " [ $iPage ] ";

    //-- next page
    //if($iPage*$RecordsPerPage >= $db->num_rows())
    if (!$is_next_record)
      $scroller_next = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormOrders_Page=".$next_page."#Orders\">";
    else
    {
      $next_page = $iPage + 1;
      $scroller_next = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormOrders_Page=".$next_page."#Orders\">";
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