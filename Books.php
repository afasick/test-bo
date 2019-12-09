<?php
 /*********************************************************************************
 *          Filename: Books.php
 *          Generated with CodeCharge  v.1.1.19
 *          PHP build 02/26/2001
 *********************************************************************************/

include ("./common.php");
include ("./Header.php");
include ("./Footer.php");

session_start();

$sFileName = "Books.php";





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
   <td valign="top">
<? AdvMenu_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Total_Show() ?>
    
   </td>
  </tr>
 </table>
 <table>
  <tr>
   <td valign="top">
<? Results_Show() ?>
    
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


function Results_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sResultsErr; //-- error string

  
  //-- transit parameters
  $transit_params = "category_id=" . tourl(strip(get_param("category_id"))) . "&name=" . tourl(strip(get_param("name"))) . "&pricemin=" . tourl(strip(get_param("pricemin"))) . "&pricemax=" . tourl(strip(get_param("pricemax"))) . "&author=" . tourl(strip(get_param("author"))) . "&";
  //-- form parameters
  $form_params = "category_id=" . tourl(get_param("category_id")) . "&name=" . tourl(get_param("name")) . "&pricemin=" . tourl(get_param("pricemin")) . "&pricemax=" . tourl(get_param("pricemax")) . "&author=" . tourl(get_param("author")) . "&";//-- SQL for order field
  $sOrder = " order by i.name Asc";

  $HasParam = false;

  $iSort = get_param("FormResults_Sorting");
  $iSorted = get_param("FormResults_Sorted");

  //-- process sort commands
  $sDirection = "";
  $sSortParams = "";
  if($iSort)
  {
    if($iSort == $iSorted)
    {
      $form_sorting = "";
      $sDirection = " DESC";
      $sSortParams = "FormResults_Sorting=" . $iSort . "&FormResults_Sorted=" . $iSort . "&";
    }
    else
    {
      $form_sorting = $iSort;
      $sDirection = " ASC";
      $sSortParams = "FormResults_Sorting=" . $iSort . "&FormResults_Sorted=" . "&";
    }
    
    if ($iSort == 1) $sOrder = " order by i.name" . $sDirection;
    if ($iSort == 2) $sOrder = " order by i.author" . $sDirection;
    if ($iSort == 3) $sOrder = " order by i.price" . $sDirection;
    if ($iSort == 4) $sOrder = " order by c.name" . $sDirection;
    if ($iSort == 5) $sOrder = " order by i.image_url" . $sDirection;
    if (!strlen($sOrder))  $sDirection = "";
  }
  

//-- table header
?>
     <table style="">
      <tr>
       <td style="background-color: #336699; text-align: Center; border-style: outset; border-width: 1" colspan="2"><a name="Results"><font style="font-size: 12pt; color: #FFFFFF; font-weight: bold">Search Results</font></a></td>
      </tr>
<?

  $sWhere = "";
  
  //-- Check author parameter and create a valid sql for where clause
  
  $pauthor = get_param("author");
  if(strlen($pauthor)) 
  {
    $HasParam = true;
    $sWhere .= "i.author like " . tosql("%".$pauthor . "%","Text");
  }
  //-- Check category_id parameter and create a valid sql for where clause
  
  $pcategory_id = get_param("category_id");
  if(is_number($pcategory_id) && strlen($pcategory_id))
    $pcategory_id = round($pcategory_id);
  else 
    $pcategory_id = "";
  if(strlen($pcategory_id)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.category_id=" . $pcategory_id;
  }
  //-- Check name parameter and create a valid sql for where clause
  
  $pname = get_param("name");
  if(strlen($pname)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.name like " . tosql("%".$pname . "%","Text");
  }
  //-- Check pricemax parameter and create a valid sql for where clause
  
  $ppricemax = get_param("pricemax");
  if(is_number($ppricemax) && strlen($ppricemax))
    $ppricemax = round($ppricemax);
  else 
    $ppricemax = "";
  if(strlen($ppricemax)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.price<" . $ppricemax;
  }
  //-- Check pricemin parameter and create a valid sql for where clause
  
  $ppricemin = get_param("pricemin");
  if(is_number($ppricemin) && strlen($ppricemin))
    $ppricemin = round($ppricemin);
  else 
    $ppricemin = "";
  if(strlen($ppricemin)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.price>" . $ppricemin;
  }
  //-- populate arrays for list of values
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " AND (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "select i.author as i_author, " . 
    "i.category_id as i_category_id, " . 
    "i.image_url as i_image_url, " . 
    "i.item_id as i_item_id, " . 
    "i.name as i_name, " . 
    "i.price as i_price, " . 
    "c.category_id as c_category_id, " . 
    "c.name as c_name " . 
    " from items i, categories c" . 
    " where c.category_id=i.category_id  ";
  
  $sSQL = $sSQL . $sWhere . $sOrder;

  //-- insert button
  
  //-- variables of the page scroller
  $iPage = get_param("FormResults_Page");
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
    
$fldimage_url="<img border=0 src=" . $fldimage_url . ">";

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $fldname = $db->f("i_name");
      $fldauthor = $db->f("i_author");
      $fldprice = $db->f("i_price");
      $fldcategory_id = $db->f("c_name");
      $fldimage_url = $db->f("i_image_url");
$fldimage_url="<img border=0 src=" . $fldimage_url . ">";
    $iCounter++;
      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Title</font> </td><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="BookDetail.php?item_id=<?= tourl($db->f("i_item_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= tohtml($fldname) ?></font></a>&nbsp;</font></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Author</font> </td><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldauthor)?>&nbsp;</font></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Price</font> </td><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldprice)?>&nbsp;</font></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Category</font> </td><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($fldcategory_id)?>&nbsp;</font></td>
      </tr>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Image URL</font> </td><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><a href="BookDetail.php?item_id=<?= tourl($db->f("i_item_id"))?>&<?=$transit_params?>"><font style="font-size: 10pt; color: #000000"><?= $fldimage_url ?></font></a>&nbsp;</font></td>
      </tr>
      <tr>
       <td colspan="2" style="background-color: #FFFFFF; border-width: 1">&nbsp;</td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record  && $iCounter < $RecordsPerPage);
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="5" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>


      </table>
    <?
    return;
  }

 
 //-- last row of the table is for scroller and "insert" link
  ?>
    
    <? if ($iPage*$RecordsPerPage < $db->num_rows() || $iPage != 1) { ?>
      <tr><td colspan="5" style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">
    <? } ?>
    
  <?
  //-- scroller
  

  if($is_next_record || $iPage != 1)
  {
    //-- previous page 
    if($iPage == 1)
      $scroller_prev = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormResults_Page=".$prev_page."#Results\">";
    else
    {
      $prev_page = $iPage - 1;
      $scroller_prev = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormResults_Page=".$prev_page."#Results\">";
    }
    echo  $scroller_prev."<font "."style=\"font-size: 10pt; color: #CE7E00; font-weight: bold\"".">Previous</font>";
    if ($scroller_prev) echo "</a>";

    //-- current page
    echo " [ $iPage ] ";

    //-- next page
    //if($iPage*$RecordsPerPage >= $db->num_rows())
    if (!$is_next_record)
      $scroller_next = "<a href_=\"".$sFileName."?".$transit_params.$sSortParams."FormResults_Page=".$next_page."#Results\">";
    else
    {
      $next_page = $iPage + 1;
      $scroller_next = "<a href=\"".$sFileName."?".$transit_params.$sSortParams."FormResults_Page=".$next_page."#Results\">";
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



function Search_Show()
{
  global $styles;
  
  $action_page = "Books.php";

  


    $fldcategory_id = strip(get_param("category_id"));
    $fldname = strip(get_param("name"));
  ?>
    <form method="GET" action="<?= $action_page ?>">
    <table style="">
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Category</font></td>
      <td style="background-color: #FFFFFF; border-width: 1"><select name="category_id"><?= get_options("select category_id, name from categories order by 2",true,false,$fldcategory_id);?></select></td>
     </tr>
     <tr>
      <td style="background-color: #FFEAC5; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #000000">Title</font></td>
      <td style="background-color: #FFFFFF; border-width: 1">
         <input type="text" name="name" maxlength="10" value="<?= tohtml($fldname) ?>" size="10" ></td>
     </tr>
     <tr>
     <td align="right" colspan="3"><input type="submit" value="Search">
     </td>     
    </tr>
     
   </table>
   </form>
<?
  
}

function AdvMenu_Show()
{
global $styles;




?>
  <table style="">
  
  <tr>
  
    <td style="background-color: #FFFFFF; border-width: 1"><a href="AdvSearch.php"><font style="font-size: 10pt; color: #000000">Advanced Search</font></a></td>
  </tr>
  </table>
<?

}


function Total_Show()
{ 
  global $sFileName;  //-- name of the current page
  
  global $db;   //-- database connection
  global $sTotalErr; //-- error string

  
  //-- form parameters
  $form_params = "category_id=" . tourl(get_param("category_id")) . "&name=" . tourl(get_param("name")) . "&author=" . tourl(get_param("author")) . "&pricemin=" . tourl(get_param("pricemin")) . "&pricemax=" . tourl(get_param("pricemax")) . "&";

//-- table header
?>
     <table style="">
<?

  $sWhere = "";
  
  //-- Check author parameter and create a valid sql for where clause
  
  $pauthor = get_param("author");
  if(strlen($pauthor)) 
  {
    $HasParam = true;
    $sWhere .= "i.author like " . tosql("%".$pauthor . "%","Text");
  }
  //-- Check category_id parameter and create a valid sql for where clause
  
  $pcategory_id = get_param("category_id");
  if(is_number($pcategory_id) && strlen($pcategory_id))
    $pcategory_id = round($pcategory_id);
  else 
    $pcategory_id = "";
  if(strlen($pcategory_id)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.category_id=" . $pcategory_id;
  }
  //-- Check name parameter and create a valid sql for where clause
  
  $pname = get_param("name");
  if(strlen($pname)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.name like " . tosql("%".$pname . "%","Text");
  }
  //-- Check pricemax parameter and create a valid sql for where clause
  
  $ppricemax = get_param("pricemax");
  if(is_number($ppricemax) && strlen($ppricemax))
    $ppricemax = round($ppricemax);
  else 
    $ppricemax = "";
  if(strlen($ppricemax)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.price<=" . $ppricemax;
  }
  //-- Check pricemin parameter and create a valid sql for where clause
  
  $ppricemin = get_param("pricemin");
  if(is_number($ppricemin) && strlen($ppricemin))
    $ppricemin = round($ppricemin);
  else 
    $ppricemin = "";
  if(strlen($ppricemin)) 
  {
    if ($sWhere != "") $sWhere .= " and ";
    $HasParam = true;
    $sWhere .= "i.price>=" . $ppricemin;
  }
  //-- populate arrays for list of values
  //-- WHERE clause for form parameters
  if ($HasParam) 
    $sWhere = " WHERE (" . $sWhere . ")";
  
  //-- complete SQL
  $sSQL = "select i.author as i_author, " . 
    "i.category_id as i_category_id, " . 
    "i.item_id as i_item_id, " . 
    "i.name as i_name, " . 
    "i.price as i_price " . 
    " from items i ";
  
$sSQL="select count(item_id) as i_item_id from items as i";
  $sSQL = $sSQL . $sWhere . $sOrder;

  //-- insert button
  

  //-- do SQL query
  $db->query($sSQL);
  
  $is_next_record=false;

  //-- show records
  if($db->next_record())
  {
    //-- default values
    

    //-- display rows
    do
    {
      //-- retrieve data from the record
      $flditem_id = $db->f("i_item_id");

      //-- display current record
    ?>
      <tr>
       <td style="background-color: #FFFFFF; border-style: inset; border-width: 0"><font style="font-size: 10pt; color: #CE7E00; font-weight: bold">Items found:</font> </td><td style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000"><?=tohtml($flditem_id)?>&nbsp;</font></td>
      </tr>
      <tr>
       <td colspan="2" style="background-color: #FFFFFF; border-width: 1">&nbsp;</td>
      </tr>
    <?
    $is_next_record = @$db->next_record();
    } while($is_next_record );
  }
  else //-- there are no records
  {
  //$db->num_rows() == 0 || ($iPage - 1)*$RecordsPerPage >= $db->num_rows())
    ?>
      <tr><td colspan="1" style="background-color: #FFFFFF; border-width: 1"><font style="font-size: 10pt; color: #000000">No records</font></td></tr>


      </table>
    <?
    return;
  }

 

  //-- the end of the last row and the end of the table
  ?>
    </table>
  <?

 
}

?>