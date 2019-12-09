<?php
 /*********************************************************************************
 *          Filename: AdminBooks.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "AdminBooks.php";



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
<? Items_Show() ?>
    
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
  
  $action_page = "AdminBooks.php";

  


    $fldcategory_id = strip(get_param("category_id"));
    $fldis_recommended = strip(get_param("is_recommended"));
  ?>
    <form method="GET" action="<?= $action_page ?>">
    <table style="">
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Category</font></td>
      <td style="background-color: #FFFFFF; border-width: 1"><select name="category_id"><?= get_options("select category_id, name from categories order by 2",true,false,$fldcategory_id);?></select></td>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Recommended</font></td>
      <td style="background-color: #FFFFFF; border-width: 1"><select name="is_recommended"><?= get_lov_options(';All;0;No;1;Yes',true,false,$fldis_recommended);?></select></td>
     <td ><input type="submit" value="Search">
     </td>     
    </tr>
     
   </table>
   </form>
<?
  
}

function Items_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sItemsErr; //-- error string

  
  //-- transit parameters
  $transit_params = "category_id=" . tourl(strip(get_param("category_id"))) . "&is_recommended=" . tourl(strip(get_param("is_recommended"))) . "&";
  //-- form parameters
  $form_params = "category_id=" . tourl(get_param("category_id")) . "&is_recommended=" . tourl(get_param("is_recommended")) . "&";

  $HasParam = false;

  $iSort = get_param("FormItems_Sorting");
  $iSorted = get_param("FormItems_Sorted");

  //-- process sort commands
  $sDirection = "";
  $sSortParams = "";
  if($iSort)
  {
    if($iSort == $iSorted)
    {
      $form_sorting = "";
      $sDirection = " DESC";
      $sSortParams = "FormItems_Sorting=" . $iSort . "&FormItems_Sorted=" . $iSort . "&";
    }
    else
    {
      $form_sorting = $iSort;
      $sDirection = " ASC";
      $sSortParams = "FormItems_Sorting=" . $iSort . "&FormItems_Sorted=" . "&";
    }
    
    if ($iSort == 1) $sOrder = " order by i.name" . $sDirection;
    if ($iSort == 2) $sOrder = " order by i.author" . $sDirection;
    if ($iSort == 3) $sOrder = " order by i.price" . $sDirection;
    if ($iSort == 4) $sOrder = " order by c.name" . $sDirection;
    if ($iSort == 5) $sOrder = " order by i.is_recommended" . $sDirection;
    if (!strlen($sOrder))  $sDirection = "";
  }
  

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="6"><a name="Items"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Books</font></a></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a ><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Edit</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormItems_Sorting=1&FormItems_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Title</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormItems_Sorting=2&FormItems_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Author</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormItems_Sorting=3&FormItems_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Price</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormItems_Sorting=4&FormItems_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Category</font></a></td>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><a href="<?=$sFileName?>?<?=$transit_params?>FormItems_Sorting=5&FormItems_Sorted=<?=$form_sorting?>&"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Recommended</font></a></td>
      </tr>
<?

  $sWhere = "";
  
  //-- Check category_id parameter and create a valid sql for where clause
  
  $pcategory_id = get_param("category_id");
  if(is_number($pcategory_id) && strlen($pcategory_id))
    $pcategory_id = round($pcategory_id);
  else 
    $pcategory_id = "";
  if(strlen($pcategory_id)) 
  {
    $HasParam = true;
    $sWhere .= "i.category_id=" . $pcategory_id;
  }
  //-- Check is_recommended parameter and create a valid sql for where clause
  
  $pis_recommended = get_param("is_recommended");
  if(is_number($pis_recommended) && strlen($pis_recommended))
    $pis_recommended = round($pis_recommended);
  else 
    $pis_recommended = "";
  if(strlen($pis_recommended)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.is_recommended=" . $pis_recommended;
  }
  //-- populate arrays for list of values
  $lov_is_recommended = get_lov_values("0;No;1;Yes");
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " AND (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "select i.author as i_author, " . 
    "i.category_id as i_category_id, " . 
    "i.is_recommended as i_is_recommended, " . 
    "i.item_id as i_item_id, " . 
    "i.name as i_name, " . 
    "i.price as i_price, " . 
    "c.category_id as c_category_id, " . 
    "c.name as c_name " . 
    " from items i, categories c" . 
    " where c.category_id=i.category_id  ";
  
  $sSQL = $sSQL . $sWhere . $sOrder;

  //-- insert button
  $form_action = "BookMaint.php";
  //-- variables of the page scroller
  $iPage = get_param("FormItems_Page");
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
      $fldname = $db->f("i_name");
      $fldauthor = $db->f("i_author");
      $fldprice = $db->f("i_price");
      $fldcategory_id = $db->f("c_name");
      $fldis_recommended = $db->f("i_is_recommended");
      $fldField1= "Edit";
    $iCounter++;
      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="BookMaint.php?item_id=<?= tourl($db->f("i_item_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldField1) ?></font></a>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldname)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldauthor)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldprice)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldcategory_id)?>&nbsp;</font></td>
       <td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?
  $fldis_recommended = $lov_is_recommended[$fldis_recommended]; 
 ?><?=tohtml($fldis_recommended)?>&nbsp;</font></td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record  && $iCounter < $RecordsPerPage);
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="6" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>
<tr><td colspan="6" style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">
      <a href="<?= $form_action ?>?<?= $transit_params ?>"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Add New</font></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

      </table>
    <?
    return;
  }

 
 //-- last row of the table is for scroller and "insert" link
  ?>
    
      <tr><td colspan="6" style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">
      <a href="<?= $form_action ?>?<?= $transit_params ?>"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Add New</font></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <?
  //-- scroller
  

  if($is_next_record || $iPage != 1)
  {
    //-- previous page 
    if($iPage == 1)
      $scroller_prev = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormItems_Page=".$prev_page."#Items\">";
    else
    {
      $prev_page = $iPage - 1;
      $scroller_prev = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormItems_Page=".$prev_page."#Items\">";
    }
    echo  $scroller_prev."<font "."style=\"font-size: 10pt; color: #CE7E00; font-weight: bold\"".">Previous</font>";
    if ($scroller_prev) echo "</a>";

    //-- current page
    echo " [ $iPage ] ";

    //-- next page
    //if($iPage*$RecordsPerPage >= $db->num_rows())
    if (!$is_next_record)
      $scroller_next = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormItems_Page=".$next_page."#Items\">";
    else
    {
      $next_page = $iPage + 1;
      $scroller_next = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormItems_Page=".$next_page."#Items\">";
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