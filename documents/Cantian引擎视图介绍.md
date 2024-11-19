# 数据目录使用量<a name="ZH-CN_TOPIC_0000001801875998"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row745316563018"><th class="cellrowborder" valign="top" width="17.4%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a>视图名称</p>
</th>
<th class="cellrowborder" valign="top" width="27.13%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a>视图说明</p>
</th>
<th class="cellrowborder" valign="top" width="14.85%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a>字段名</p>
</th>
<th class="cellrowborder" valign="top" width="9.8%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a>字段定义</p>
</th>
<th class="cellrowborder" valign="top" width="18.88%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a>字段说明</p>
</th>
<th class="cellrowborder" valign="top" width="11.940000000000001%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a>备注</p>
</th>
</tr>
</thead>
<tbody><tr id="row3453185153015"><td class="cellrowborder" valign="top" width="17.4%" headers="mcps1.1.7.1.1 "><p id="p0453356305"><a name="p0453356305"></a><a name="p0453356305"></a>cantian.dv_data_files</p>
</td>
<td class="cellrowborder" valign="top" width="27.13%" headers="mcps1.1.7.1.2 "><p id="p194539519308"><a name="p194539519308"></a><a name="p194539519308"></a>查看当前数据库的数据文件分配情况。</p>
</td>
<td class="cellrowborder" valign="top" width="14.85%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.88%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.940000000000001%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row845345133018"><td class="cellrowborder" rowspan="13" valign="top" width="17.4%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="13" valign="top" width="27.13%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.85%" headers="mcps1.1.7.1.3 "><p id="p1645365113018"><a name="p1645365113018"></a><a name="p1645365113018"></a>ID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8%" headers="mcps1.1.7.1.4 "><p id="p745313514307"><a name="p745313514307"></a><a name="p745313514307"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.88%" headers="mcps1.1.7.1.5 "><p id="p1145355163010"><a name="p1145355163010"></a><a name="p1145355163010"></a>数据文件的ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.940000000000001%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row445312514303"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p144541953309"><a name="p144541953309"></a><a name="p144541953309"></a>TABLESPACE_ID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19454450303"><a name="p19454450303"></a><a name="p19454450303"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p445414573014"><a name="p445414573014"></a><a name="p445414573014"></a>数据文件所属的表空间ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row145411573014"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p34545512302"><a name="p34545512302"></a><a name="p34545512302"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p20454165143016"><a name="p20454165143016"></a><a name="p20454165143016"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1145413523011"><a name="p1145413523011"></a><a name="p1145413523011"></a>数据文件的状态：ONLINE/OFFLINE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1945417511302"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1545412593016"><a name="p1545412593016"></a><a name="p1545412593016"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p44541959308"><a name="p44541959308"></a><a name="p44541959308"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6454756305"><a name="p6454756305"></a><a name="p6454756305"></a>数据文件的类型：FILE/RAW/CFS。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1454135163012"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p15454759309"><a name="p15454759309"></a><a name="p15454759309"></a>FILE_NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19454651304"><a name="p19454651304"></a><a name="p19454651304"></a>VARCHAR(256)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p134541859301"><a name="p134541859301"></a><a name="p134541859301"></a>数据文件的文件名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row245414510305"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19454135143014"><a name="p19454135143014"></a><a name="p19454135143014"></a>BYTES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p245411573010"><a name="p245411573010"></a><a name="p245411573010"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1645417583016"><a name="p1645417583016"></a><a name="p1645417583016"></a>数据文件的大小。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row17454145163011"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1945465123014"><a name="p1945465123014"></a><a name="p1945465123014"></a>AUTO_EXTEND</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p245410513011"><a name="p245410513011"></a><a name="p245410513011"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1345411515303"><a name="p1345411515303"></a><a name="p1345411515303"></a>是否可自动扩展。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row10454257303"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1045416510305"><a name="p1045416510305"></a><a name="p1045416510305"></a>AUTO_EXTEND_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p134540533019"><a name="p134540533019"></a><a name="p134540533019"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17454956303"><a name="p17454956303"></a><a name="p17454956303"></a>自动扩展的大小。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1645485113020"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1045416515307"><a name="p1045416515307"></a><a name="p1045416515307"></a>MAX_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p645419533011"><a name="p645419533011"></a><a name="p645419533011"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p54540518306"><a name="p54540518306"></a><a name="p54540518306"></a>可扩展的最大文件大小。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row14454125203019"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p745419533012"><a name="p745419533012"></a><a name="p745419533012"></a>HIGH_WATER_MARK</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p9454135123012"><a name="p9454135123012"></a><a name="p9454135123012"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p18454115113010"><a name="p18454115113010"></a><a name="p18454115113010"></a>文件使用页数的高水位线（数据文件的最大page数）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2045420516302"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p94550513303"><a name="p94550513303"></a><a name="p94550513303"></a>ALLOC_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p64551356305"><a name="p64551356305"></a><a name="p64551356305"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1345514513011"><a name="p1345514513011"></a><a name="p1345514513011"></a>GaussDB视图内未定义。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row245565123017"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p745565113019"><a name="p745565113019"></a><a name="p745565113019"></a>COMPRESSION</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p104553511302"><a name="p104553511302"></a><a name="p104553511302"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p18455135153020"><a name="p18455135153020"></a><a name="p18455135153020"></a>GaussDB视图内未定义。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row345514573012"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p164551655307"><a name="p164551655307"></a><a name="p164551655307"></a>PUNCHED</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p245516563014"><a name="p245516563014"></a><a name="p245516563014"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p174551951309"><a name="p174551951309"></a><a name="p174551951309"></a>GaussDB视图内未定义。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1641920501723"><td class="cellrowborder" valign="top" width="17.4%" headers="mcps1.1.7.1.1 "><p id="p489432011316"><a name="p489432011316"></a><a name="p489432011316"></a>cantian.dv_tablespaces</p>
</td>
<td class="cellrowborder" valign="top" width="27.13%" headers="mcps1.1.7.1.2 "><p id="p1150103111596"><a name="p1150103111596"></a><a name="p1150103111596"></a>查看所有用户的数据文件信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.85%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.88%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.940000000000001%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row3419195012210"><td class="cellrowborder" rowspan="14" valign="top" width="17.4%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="14" valign="top" width="27.13%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.85%" headers="mcps1.1.7.1.3 "><p id="p68197121124"><a name="p68197121124"></a><a name="p68197121124"></a>ID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8%" headers="mcps1.1.7.1.4 "><p id="p04491021126"><a name="p04491021126"></a><a name="p04491021126"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.88%" headers="mcps1.1.7.1.5 "><p id="p64497211222"><a name="p64497211222"></a><a name="p64497211222"></a>表空间的ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.940000000000001%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row841911502027"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p178191312320"><a name="p178191312320"></a><a name="p178191312320"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p044992116220"><a name="p044992116220"></a><a name="p044992116220"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12449132118218"><a name="p12449132118218"></a><a name="p12449132118218"></a>表空间名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row041915506218"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p681919124218"><a name="p681919124218"></a><a name="p681919124218"></a>TEMPORARY</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p104498211210"><a name="p104498211210"></a><a name="p104498211210"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1244912211326"><a name="p1244912211326"></a><a name="p1244912211326"></a>是否为临时空间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row241955015215"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p981914122210"><a name="p981914122210"></a><a name="p981914122210"></a>IN_MEMORY</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p444962114218"><a name="p444962114218"></a><a name="p444962114218"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p944962115216"><a name="p944962115216"></a><a name="p944962115216"></a>是否IN MEMORY。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row641975014215"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1681916122022"><a name="p1681916122022"></a><a name="p1681916122022"></a>AUTO_PURGE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p174493216210"><a name="p174493216210"></a><a name="p174493216210"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p14449521525"><a name="p14449521525"></a><a name="p14449521525"></a>表空间进行扩展时，是否优先进行回收站空间自动回收。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1341918501725"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p881911121729"><a name="p881911121729"></a><a name="p881911121729"></a>EXTENT_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p044916211722"><a name="p044916211722"></a><a name="p044916211722"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1244952119217"><a name="p1244952119217"></a><a name="p1244952119217"></a>扩展大小。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row441955016210"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p3819612625"><a name="p3819612625"></a><a name="p3819612625"></a>SEGMENT_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p17449521821"><a name="p17449521821"></a><a name="p17449521821"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p34490211229"><a name="p34490211229"></a><a name="p34490211229"></a>段数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row12419150227"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p4819101215216"><a name="p4819101215216"></a><a name="p4819101215216"></a>FILE_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1044915216212"><a name="p1044915216212"></a><a name="p1044915216212"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p0449621624"><a name="p0449621624"></a><a name="p0449621624"></a>文件个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1741911508214"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p158199122215"><a name="p158199122215"></a><a name="p158199122215"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p104495211228"><a name="p104495211228"></a><a name="p104495211228"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p145012211725"><a name="p145012211725"></a><a name="p145012211725"></a>表空间状态：ONLINE/OFFLINE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row0419125014217"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p15819412629"><a name="p15819412629"></a><a name="p15819412629"></a>AUTO_OFFLINE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19450102117216"><a name="p19450102117216"></a><a name="p19450102117216"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p44508211219"><a name="p44508211219"></a><a name="p44508211219"></a>表空间是否开启自动离线。取值范围：ON/OFF。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row84190501721"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p281910122028"><a name="p281910122028"></a><a name="p281910122028"></a>EXTENT_MANAGEMENT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p9450192116219"><a name="p9450192116219"></a><a name="p9450192116219"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p11450182113216"><a name="p11450182113216"></a><a name="p11450182113216"></a>表空间管理方式。取值范围：NORMAL/MAP。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row74191550322"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19819131213215"><a name="p19819131213215"></a><a name="p19819131213215"></a>EXTENT_ALLOCATION</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1945092110213"><a name="p1945092110213"></a><a name="p1945092110213"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p124506211921"><a name="p124506211921"></a><a name="p124506211921"></a>EXTENT分配方式。取值范围：UNIFORM/AUTO。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row114198502212"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p15819151219214"><a name="p15819151219214"></a><a name="p15819151219214"></a>ENCRYPT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19450142111217"><a name="p19450142111217"></a><a name="p19450142111217"></a>VARCHAR(8)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p13450102110220"><a name="p13450102110220"></a><a name="p13450102110220"></a>GaussDB视图内未定义。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16419650321"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1681915121325"><a name="p1681915121325"></a><a name="p1681915121325"></a>PUNCHED_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p10450921023"><a name="p10450921023"></a><a name="p10450921023"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1245052115220"><a name="p1245052115220"></a><a name="p1245052115220"></a>GaussDB视图内未定义。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1964618307611"><td class="cellrowborder" valign="top" width="17.4%" headers="mcps1.1.7.1.1 "><p id="p379681711265"><a name="p379681711265"></a><a name="p379681711265"></a>cantian.cantian_data_files</p>
</td>
<td class="cellrowborder" valign="top" width="27.13%" headers="mcps1.1.7.1.2 "><p id="p97963172261"><a name="p97963172261"></a><a name="p97963172261"></a>查看当前数据库的数据文件分配情况。</p>
</td>
<td class="cellrowborder" valign="top" width="14.85%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.88%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.940000000000001%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row38761282125"><td class="cellrowborder" rowspan="14" valign="top" width="17.4%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="14" valign="top" width="27.13%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.85%" headers="mcps1.1.7.1.3 "><p id="p137965178269"><a name="p137965178269"></a><a name="p137965178269"></a>FILE_NAME</p>
</td>
<td class="cellrowborder" valign="top" width="9.8%" headers="mcps1.1.7.1.4 "><p id="p187962172265"><a name="p187962172265"></a><a name="p187962172265"></a>VARCHAR(256 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" width="18.88%" headers="mcps1.1.7.1.5 "><p id="p3796151782618"><a name="p3796151782618"></a><a name="p3796151782618"></a>文件名称。</p>
</td>
<td class="cellrowborder" valign="top" width="11.940000000000001%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row22861113127"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p179613178261"><a name="p179613178261"></a><a name="p179613178261"></a>FILE_ID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p9796917152614"><a name="p9796917152614"></a><a name="p9796917152614"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p67967179265"><a name="p67967179265"></a><a name="p67967179265"></a>文件编号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row383517241126"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1879611172263"><a name="p1879611172263"></a><a name="p1879611172263"></a>TABLESPACE_NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2796101713268"><a name="p2796101713268"></a><a name="p2796101713268"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p18796201702619"><a name="p18796201702619"></a><a name="p18796201702619"></a>文件所属的表空间名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row7721202761214"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p77961817192616"><a name="p77961817192616"></a><a name="p77961817192616"></a>BYTES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p10796717162615"><a name="p10796717162615"></a><a name="p10796717162615"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p2797171719267"><a name="p2797171719267"></a><a name="p2797171719267"></a>文件大小（以字节为单位）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2320630171214"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p11797617162612"><a name="p11797617162612"></a><a name="p11797617162612"></a>BLOCKS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p679761722620"><a name="p679761722620"></a><a name="p679761722620"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1679741762613"><a name="p1679741762613"></a><a name="p1679741762613"></a>占用块数量。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13353533101220"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p079716176268"><a name="p079716176268"></a><a name="p079716176268"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p16797417192611"><a name="p16797417192611"></a><a name="p16797417192611"></a>CHAR(5 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p107971717112613"><a name="p107971717112613"></a><a name="p107971717112613"></a>文件状态（VALID/INVALID）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18869235131214"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p157972177268"><a name="p157972177268"></a><a name="p157972177268"></a>RELATIVE_FNO</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p8797121711269"><a name="p8797121711269"></a><a name="p8797121711269"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p3797017102613"><a name="p3797017102613"></a><a name="p3797017102613"></a>关联文件的编号，兼容字段，同FILE_ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row129861379128"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1879711762610"><a name="p1879711762610"></a><a name="p1879711762610"></a>AUTOEXTENSIBLE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p12797141782612"><a name="p12797141782612"></a><a name="p12797141782612"></a>CHAR(3 BYTE）</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1879721717263"><a name="p1879721717263"></a><a name="p1879721717263"></a>文件写满后是否会自动扩展，YES：是，NO：否。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row101004013121"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19797317112618"><a name="p19797317112618"></a><a name="p19797317112618"></a>MAXBYTES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p167971417102614"><a name="p167971417102614"></a><a name="p167971417102614"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p7797171782615"><a name="p7797171782615"></a><a name="p7797171782615"></a>支持文件自动扩展时，允许扩展的最大字节数。如果AUTOEXTENSIBLE为NO，则为0。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row7985104116124"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p137981817172619"><a name="p137981817172619"></a><a name="p137981817172619"></a>MAXBLOCKS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p127981517182616"><a name="p127981517182616"></a><a name="p127981517182616"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p177985178260"><a name="p177985178260"></a><a name="p177985178260"></a>支持文件自动扩展时，允许扩展的最大块数。如果AUTOEXTENSIBLE为NO，则为0。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2656144919128"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p9798117182616"><a name="p9798117182616"></a><a name="p9798117182616"></a>INCREMENT_BY</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p279851715261"><a name="p279851715261"></a><a name="p279851715261"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p11798161712611"><a name="p11798161712611"></a><a name="p11798161712611"></a>支持文件自动扩展时，每次扩展的大小，单位：字节。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row178901751191214"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p979881715268"><a name="p979881715268"></a><a name="p979881715268"></a>USER_BYTES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19798101711266"><a name="p19798101711266"></a><a name="p19798101711266"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p187981017172613"><a name="p187981017172613"></a><a name="p187981017172613"></a>用户能够使用大小，单位：字节。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row14954115361218"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1279813178266"><a name="p1279813178266"></a><a name="p1279813178266"></a>USER_BLOCKS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p279861762614"><a name="p279861762614"></a><a name="p279861762614"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p127981217182614"><a name="p127981217182614"></a><a name="p127981217182614"></a>用户能够使用大小，单位：块。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1676645618129"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1798917202616"><a name="p1798917202616"></a><a name="p1798917202616"></a>ONLINE_STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p10798917192619"><a name="p10798917192619"></a><a name="p10798917192619"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17798217142613"><a name="p17798217142613"></a><a name="p17798217142613"></a>文件是否在线。ONLINE：是；OFFLINE：否。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

# 节点/版本等状态信息<a name="ZH-CN_TOPIC_0000001866298573"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row1843045719232"><th class="cellrowborder" valign="top" width="17.391739173917394%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b7753114673611"><a name="b7753114673611"></a><a name="b7753114673611"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="27.14271427142714%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b17621346163614"><a name="b17621346163614"></a><a name="b17621346163614"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="14.84148414841484%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b6771194683612"><a name="b6771194683612"></a><a name="b6771194683612"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="9.8009800980098%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b977254616363"><a name="b977254616363"></a><a name="b977254616363"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="18.891889188918892%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b6772194693614"><a name="b6772194693614"></a><a name="b6772194693614"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b17772346133618"><a name="b17772346133618"></a><a name="b17772346133618"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row134717612125"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p11485651212"><a name="p11485651212"></a><a name="p11485651212"></a>cantian.node_info</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p19481663121"><a name="p19481663121"></a><a name="p19481663121"></a>查看当前数据库实例的基本信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row44584514308"><td class="cellrowborder" rowspan="6" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="6" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1245815519300"><a name="p1245815519300"></a><a name="p1245815519300"></a>INST_ID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p17458854309"><a name="p17458854309"></a><a name="p17458854309"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p1245811573017"><a name="p1245811573017"></a><a name="p1245811573017"></a>当前节点在集群中的实例ID，两个节点时取值：0或1。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row114584533019"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p14458553306"><a name="p14458553306"></a><a name="p14458553306"></a>ADDRESS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p24589513306"><a name="p24589513306"></a><a name="p24589513306"></a>VARCHAR(32)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1645811514301"><a name="p1645811514301"></a><a name="p1645811514301"></a>集群中实例间通信IP地址。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row94581959302"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p17458175143012"><a name="p17458175143012"></a><a name="p17458175143012"></a>INTERCONNECT_PORT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p74581056305"><a name="p74581056305"></a><a name="p74581056305"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p2045814512300"><a name="p2045814512300"></a><a name="p2045814512300"></a>集群中实例间通信使用的端口号，节点0使用1601，节点1使用1602。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row44584512302"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p4458205183020"><a name="p4458205183020"></a><a name="p4458205183020"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p745816510302"><a name="p745816510302"></a><a name="p745816510302"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1245815163012"><a name="p1245815163012"></a><a name="p1245815163012"></a>集群中实例间通信类型：TCP/UC。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row04584514303"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p3458185153011"><a name="p3458185153011"></a><a name="p3458185153011"></a>CHANNEL_NUM</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p445816543016"><a name="p445816543016"></a><a name="p445816543016"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p5458125183011"><a name="p5458125183011"></a><a name="p5458125183011"></a>客户端会向服务端发起建立的逻辑链路数量。在TCP下，该链路是单向的，只能从客户端向服务端发送消息，在UC下，该链路是双向的，既用于客户端向服务端发，也用于服务端向客户端发。UC模式单向3条逻辑链路；TCP模式单向32条逻辑链路。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18458550306"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p6458753305"><a name="p6458753305"></a><a name="p6458753305"></a>POOL_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p5458651302"><a name="p5458651302"></a><a name="p5458651302"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p54581657305"><a name="p54581657305"></a><a name="p54581657305"></a>节点间通信预留接收消息buffer的数量，默认16384。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9127194145718"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p412724175717"><a name="p412724175717"></a><a name="p412724175717"></a>cantian.dv_reform_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p191271241135716"><a name="p191271241135716"></a><a name="p191271241135716"></a>查看reform关键信息视图。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row512774195713"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p12127114114575"><a name="p12127114114575"></a><a name="p12127114114575"></a>STATISTIC#</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p171271941105713"><a name="p171271941105713"></a><a name="p171271941105713"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p031435010116"><a name="p031435010116"></a><a name="p031435010116"></a>统计项编号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row51281841175716"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1312816411577"><a name="p1312816411577"></a><a name="p1312816411577"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p87351642606"><a name="p87351642606"></a><a name="p87351642606"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p91281941165718"><a name="p91281941165718"></a><a name="p91281941165718"></a>统计项名称。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row101280412572"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p61281241145719"><a name="p61281241145719"></a><a name="p61281241145719"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p17128194114578"><a name="p17128194114578"></a><a name="p17128194114578"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p141283419574"><a name="p141283419574"></a><a name="p141283419574"></a>统计项值。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11128174195711"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p5128204105715"><a name="p5128204105715"></a><a name="p5128204105715"></a>INFO</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p123343519118"><a name="p123343519118"></a><a name="p123343519118"></a>VARCHAR(1024)</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p14128741115710"><a name="p14128741115710"></a><a name="p14128741115710"></a>统计项简介。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row924614403410"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p65941933134"><a name="p65941933134"></a><a name="p65941933134"></a>cantian.dv_parameters</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p259463101319"><a name="p259463101319"></a><a name="p259463101319"></a>查看设置变量信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1224616473417"><td class="cellrowborder" rowspan="10" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="10" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p164664593015"><a name="p164664593015"></a><a name="p164664593015"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p174668583010"><a name="p174668583010"></a><a name="p174668583010"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p8466195143013"><a name="p8466195143013"></a><a name="p8466195143013"></a>参数名。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row824616483412"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p104667593010"><a name="p104667593010"></a><a name="p104667593010"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1246615503017"><a name="p1246615503017"></a><a name="p1246615503017"></a>VARCHAR(2048)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p84669573013"><a name="p84669573013"></a><a name="p84669573013"></a>参数值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row5246843347"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p34664513301"><a name="p34664513301"></a><a name="p34664513301"></a>RUNTIME_VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p546645133019"><a name="p546645133019"></a><a name="p546645133019"></a>VARCHAR(2048)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p44664513011"><a name="p44664513011"></a><a name="p44664513011"></a>参数的实时运行值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row172466411344"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1646617518302"><a name="p1646617518302"></a><a name="p1646617518302"></a>DEFAULT_VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p946614516303"><a name="p946614516303"></a><a name="p946614516303"></a>VARCHAR(2048)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p2046613519309"><a name="p2046613519309"></a><a name="p2046613519309"></a>参数默认值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row02461143344"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p24669513020"><a name="p24669513020"></a><a name="p24669513020"></a>ISDEFAULT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p17466254308"><a name="p17466254308"></a><a name="p17466254308"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p34664533018"><a name="p34664533018"></a><a name="p34664533018"></a>参数是否修改过。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row124610416346"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p04672513302"><a name="p04672513302"></a><a name="p04672513302"></a>MODIFIABLE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p11467155113020"><a name="p11467155113020"></a><a name="p11467155113020"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p346715503014"><a name="p346715503014"></a><a name="p346715503014"></a>参数是否可修改。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9246846342"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p174675511304"><a name="p174675511304"></a><a name="p174675511304"></a>DESCRIPTION</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p164671950302"><a name="p164671950302"></a><a name="p164671950302"></a>VARCHAR(2048)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1946710517306"><a name="p1946710517306"></a><a name="p1946710517306"></a>参数描述。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11246043343"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p17467155153014"><a name="p17467155153014"></a><a name="p17467155153014"></a>RANGE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p346785143011"><a name="p346785143011"></a><a name="p346785143011"></a>VARCHAR(2048)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p84671593015"><a name="p84671593015"></a><a name="p84671593015"></a>参数设置范围。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13246104143414"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1646775103012"><a name="p1646775103012"></a><a name="p1646775103012"></a>DATATYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p184671658306"><a name="p184671658306"></a><a name="p184671658306"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17467105153017"><a name="p17467105153017"></a><a name="p17467105153017"></a>参数类型。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row182469413417"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p13467153308"><a name="p13467153308"></a><a name="p13467153308"></a>EFFECTIVE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p174671513020"><a name="p174671513020"></a><a name="p174671513020"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p164676519305"><a name="p164676519305"></a><a name="p164676519305"></a>参数生效等级：reboot/reconnect/immediately。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row449181618351"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p15201057308"><a name="p15201057308"></a><a name="p15201057308"></a>cantian.dv_version</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p1052055143020"><a name="p1052055143020"></a><a name="p1052055143020"></a>提供内核版本信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1949171611353"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p452013511304"><a name="p452013511304"></a><a name="p452013511304"></a>VERSION</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p2520175103014"><a name="p2520175103014"></a><a name="p2520175103014"></a>VARCHAR(80)</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p852017518306"><a name="p852017518306"></a><a name="p852017518306"></a>版本信息。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row681105211532"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p946725133016"><a name="p946725133016"></a><a name="p946725133016"></a>cantian.dv_sys_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p9467165123014"><a name="p9467165123014"></a><a name="p9467165123014"></a>查询系统的基础统计，包括sql执行情况，读写盘时延等信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row481195218530"><td class="cellrowborder" rowspan="4" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="4" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1946718511306"><a name="p1946718511306"></a><a name="p1946718511306"></a>STATISTIC#</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p3467653304"><a name="p3467653304"></a><a name="p3467653304"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p5467450303"><a name="p5467450303"></a><a name="p5467450303"></a>统计项编号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row08114521536"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1546795203012"><a name="p1546795203012"></a><a name="p1546795203012"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2467125173013"><a name="p2467125173013"></a><a name="p2467125173013"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p174679583015"><a name="p174679583015"></a><a name="p174679583015"></a>统计项名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row58112052115319"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p946755123010"><a name="p946755123010"></a><a name="p946755123010"></a>CLASS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p134678520309"><a name="p134678520309"></a><a name="p134678520309"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10467105113017"><a name="p10467105113017"></a><a name="p10467105113017"></a>统计类型：</p>
<a name="ul159361924163313"></a><a name="ul159361924163313"></a><ul id="ul159361924163313"><li>0：SQL类型</li><li>1：Kernel类型</li><li>2：Instance类型</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row68111052175319"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p146845193013"><a name="p146845193013"></a><a name="p146845193013"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124685563018"><a name="p124685563018"></a><a name="p124685563018"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p8468195123014"><a name="p8468195123014"></a><a name="p8468195123014"></a>统计项值</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row151719586556"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p1249019518302"><a name="p1249019518302"></a><a name="p1249019518302"></a>cantian.dv_sessions</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p13490755303"><a name="p13490755303"></a><a name="p13490755303"></a>查询当前各个会话执行的sql语句。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row517165818557"><td class="cellrowborder" rowspan="67" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="67" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1449085163013"><a name="p1449085163013"></a><a name="p1449085163013"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p749095153010"><a name="p749095153010"></a><a name="p749095153010"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p849035113019"><a name="p849035113019"></a><a name="p849035113019"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row141785820559"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p124918514304"><a name="p124918514304"></a><a name="p124918514304"></a>SPID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19491458309"><a name="p19491458309"></a><a name="p19491458309"></a>VARCHAR(11)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p174911655308"><a name="p174911655308"></a><a name="p174911655308"></a>会话所在的线程ID。对于缓存在SESSION池中未在运行的会话，其SPID为0。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1417115820553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p849112533012"><a name="p849112533012"></a><a name="p849112533012"></a>SERIAL#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p54918513016"><a name="p54918513016"></a><a name="p54918513016"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1949114583010"><a name="p1949114583010"></a><a name="p1949114583010"></a>会话序列号。用于唯一标识会话的对象。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1817958195511"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p3491454302"><a name="p3491454302"></a><a name="p3491454302"></a>USER#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p134911852302"><a name="p134911852302"></a><a name="p134911852302"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12491957306"><a name="p12491957306"></a><a name="p12491957306"></a>当前会话登录的用户ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row71717587553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p114914519301"><a name="p114914519301"></a><a name="p114914519301"></a>USERNAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p18491054308"><a name="p18491054308"></a><a name="p18491054308"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p2491752300"><a name="p2491752300"></a><a name="p2491752300"></a>当前会话登录的用户名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2179580557"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1849113513015"><a name="p1849113513015"></a><a name="p1849113513015"></a>CURR_SCHEMA</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p049118583010"><a name="p049118583010"></a><a name="p049118583010"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p8491353306"><a name="p8491353306"></a><a name="p8491353306"></a>当前会话登录的SCHEMA。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1217185895520"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1849114503017"><a name="p1849114503017"></a><a name="p1849114503017"></a>PIPE_TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p34919515302"><a name="p34919515302"></a><a name="p34919515302"></a>VARCHAR(20)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p949116519309"><a name="p949116519309"></a><a name="p949116519309"></a>SESSION管道类型：TCP/SSL/UDS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9171958145513"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p15491105173018"><a name="p15491105173018"></a><a name="p15491105173018"></a>CLIENT_IP</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p94919520306"><a name="p94919520306"></a><a name="p94919520306"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p174911756302"><a name="p174911756302"></a><a name="p174911756302"></a>当前会话登录的客户端IP。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row117185818557"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1491155113010"><a name="p1491155113010"></a><a name="p1491155113010"></a>CLIENT_PORT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p64912514308"><a name="p64912514308"></a><a name="p64912514308"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p34910543017"><a name="p34910543017"></a><a name="p34910543017"></a>当前会话登录的客户端端口号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row617135845514"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p17491195153017"><a name="p17491195153017"></a><a name="p17491195153017"></a>CLIENT_UDS_PATH</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p144914513016"><a name="p144914513016"></a><a name="p144914513016"></a>VARCHAR(108)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p949165133018"><a name="p949165133018"></a><a name="p949165133018"></a>客户端UDS路径。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1217145819555"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p749135113017"><a name="p749135113017"></a><a name="p749135113017"></a>SERVER_IP</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p204911855304"><a name="p204911855304"></a><a name="p204911855304"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1249111563013"><a name="p1249111563013"></a><a name="p1249111563013"></a>当前会话服务端的IP。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1617185811557"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p174929543016"><a name="p174929543016"></a><a name="p174929543016"></a>SERVER_PORT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p64921750309"><a name="p64921750309"></a><a name="p64921750309"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p164924583010"><a name="p164924583010"></a><a name="p164924583010"></a>当前会话服务端的端口号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row517858195510"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1949210514301"><a name="p1949210514301"></a><a name="p1949210514301"></a>SERVER_UDS_PATH</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124924519309"><a name="p124924519309"></a><a name="p124924519309"></a>VARCHAR(108)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p184921658305"><a name="p184921658305"></a><a name="p184921658305"></a>服务端UDS路径。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row117165812557"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1492135143019"><a name="p1492135143019"></a><a name="p1492135143019"></a>SERVER_MODE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p349216512302"><a name="p349216512302"></a><a name="p349216512302"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p849217593012"><a name="p849217593012"></a><a name="p849217593012"></a>当前会话服务模式：均显示为MIXTURE（混合）模式。</p>
<p id="p13492135203010"><a name="p13492135203010"></a><a name="p13492135203010"></a>当前会话的实际服务模式，取决于参数SESSIONS、OPTIMIZED_WORKER_THREADS以及实际连接数：</p>
<a name="ul5723162919383"></a><a name="ul5723162919383"></a><ul id="ul5723162919383"><li>SESSIONS小于OPTIMIZED_WORKER_THREADS时，当前会话只能运行于DEDICATED（独占）模式。</li><li>SESSIONS大于OPTIMIZED_WORKER_THREADS时，若实际连接数大于OPTIMIZED_WORKER_THREADS，当前会话运行于SHARED（共享）模式，否则运行于DEDICATED（独占）模式，此种模式称为MIXTURE（混合）模式。</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row131715589558"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p8492150304"><a name="p8492150304"></a><a name="p8492150304"></a>OSUSER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1249211513301"><a name="p1249211513301"></a><a name="p1249211513301"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p134921050302"><a name="p134921050302"></a><a name="p134921050302"></a>当前会话登录的客户端所在的操作系统用户信息。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row617458135512"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p949217523019"><a name="p949217523019"></a><a name="p949217523019"></a>MACHINE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1749210573020"><a name="p1749210573020"></a><a name="p1749210573020"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1849218513012"><a name="p1849218513012"></a><a name="p1849218513012"></a>当前会话登录的客户端所在的机器信息。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row417458155514"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p149215563019"><a name="p149215563019"></a><a name="p149215563019"></a>PROGRAM</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1049214517303"><a name="p1049214517303"></a><a name="p1049214517303"></a>VARCHAR(256)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p104923512306"><a name="p104923512306"></a><a name="p104923512306"></a>当前会话登录的客户端名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row31785855515"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p049219511303"><a name="p049219511303"></a><a name="p049219511303"></a>AUTO_COMMIT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1849255133017"><a name="p1849255133017"></a><a name="p1849255133017"></a>BOOLEAN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p74922515304"><a name="p74922515304"></a><a name="p74922515304"></a>自动提交。GS_TRUE 执行语句后直接提交。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row151718588553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p11492359305"><a name="p11492359305"></a><a name="p11492359305"></a>CLIENT_VERSION</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p349225143013"><a name="p349225143013"></a><a name="p349225143013"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1949225183011"><a name="p1949225183011"></a><a name="p1949225183011"></a>客户端版本号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1017658165518"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p64930519303"><a name="p64930519303"></a><a name="p64930519303"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124932059303"><a name="p124932059303"></a><a name="p124932059303"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1449312513020"><a name="p1449312513020"></a><a name="p1449312513020"></a>当前会话类型：</p>
<a name="ul1622618913393"></a><a name="ul1622618913393"></a><ul id="ul1622618913393"><li>BACKGROUND（后台）</li><li>AUTONOMOUS（自治事务）</li><li>USER（用户）</li><li>REPLICA日志复制</li><li>JOB</li><li>EMERG(连接池满，SYS连接独占agent会话类型)</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row6177589554"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p194939512300"><a name="p194939512300"></a><a name="p194939512300"></a>LOGON_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p16493165173013"><a name="p16493165173013"></a><a name="p16493165173013"></a>DATETIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p3493175113013"><a name="p3493175113013"></a><a name="p3493175113013"></a>当前会话的登录时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row12171158135515"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p164931455305"><a name="p164931455305"></a><a name="p164931455305"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1449312573018"><a name="p1449312573018"></a><a name="p1449312573018"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p184934513012"><a name="p184934513012"></a><a name="p184934513012"></a>当前会话的状态：</p>
<a name="ul12265925133918"></a><a name="ul12265925133918"></a><ul id="ul12265925133918"><li>IN-ACTIVE（待机状态）</li><li>ACTIVE（执行状态）</li><li>CANCELED（被取消，待回收状态）</li><li>KILLED（被杀死，待回收状态）</li><li>SUSPENSION(暂停，开启自治事务后原会话挂起)</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row12171858135510"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p124930514300"><a name="p124930514300"></a><a name="p124930514300"></a>LOCK_WAIT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1549314516302"><a name="p1549314516302"></a><a name="p1549314516302"></a>VARCHAR(4)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p14931853305"><a name="p14931853305"></a><a name="p14931853305"></a>是否存在锁等待。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row91775818551"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p184932515304"><a name="p184932515304"></a><a name="p184932515304"></a>WAIT_SID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124931855306"><a name="p124931855306"></a><a name="p124931855306"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p94931056304"><a name="p94931056304"></a><a name="p94931056304"></a>锁等待的SESSION ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11171658185517"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p174931155306"><a name="p174931155306"></a><a name="p174931155306"></a>EXECUTIONS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p449375173019"><a name="p449375173019"></a><a name="p449375173019"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p20493352301"><a name="p20493352301"></a><a name="p20493352301"></a>SQL执行数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row317115812558"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p449319533015"><a name="p449319533015"></a><a name="p449319533015"></a>SIMPLE_QUERIES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p184931533016"><a name="p184931533016"></a><a name="p184931533016"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p114931755304"><a name="p114931755304"></a><a name="p114931755304"></a>简单查询语句执行数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row417858125510"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p164933503020"><a name="p164933503020"></a><a name="p164933503020"></a>DISK_READS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p849335163017"><a name="p849335163017"></a><a name="p849335163017"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p5493195173019"><a name="p5493195173019"></a><a name="p5493195173019"></a>磁盘读数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row111705865516"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p104938518307"><a name="p104938518307"></a><a name="p104938518307"></a>BUFFER_GETS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p44931859305"><a name="p44931859305"></a><a name="p44931859305"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p349316520302"><a name="p349316520302"></a><a name="p349316520302"></a>缓存读数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row8174582558"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1449455113014"><a name="p1449455113014"></a><a name="p1449455113014"></a>CR_GETS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p64941959309"><a name="p64941959309"></a><a name="p64941959309"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p144941754300"><a name="p144941754300"></a><a name="p144941754300"></a>一致性页面缓存读数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row17172583553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p84941058305"><a name="p84941058305"></a><a name="p84941058305"></a>CURRENT_SQL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p64946563012"><a name="p64946563012"></a><a name="p64946563012"></a>VARCHAR(1024)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p149414553013"><a name="p149414553013"></a><a name="p149414553013"></a>正在执行的SQL语句（只显示DML）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row6172058165513"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1549413523010"><a name="p1549413523010"></a><a name="p1549413523010"></a>SQL_EXEC_START</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p44949523018"><a name="p44949523018"></a><a name="p44949523018"></a>DATETIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p15494165143011"><a name="p15494165143011"></a><a name="p15494165143011"></a>开始执行SQL语句的时间点。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16171586554"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p10494853301"><a name="p10494853301"></a><a name="p10494853301"></a>SQL_ID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1849435133018"><a name="p1849435133018"></a><a name="p1849435133018"></a>VARCHAR(11)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p74941259300"><a name="p74941259300"></a><a name="p74941259300"></a>当前执行sql hash值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1517558135510"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p194941956300"><a name="p194941956300"></a><a name="p194941956300"></a>ATOMIC_OPERS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p174946553016"><a name="p174946553016"></a><a name="p174946553016"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p749417553012"><a name="p749417553012"></a><a name="p749417553012"></a>原子操作数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row181775814559"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p54943518302"><a name="p54943518302"></a><a name="p54943518302"></a>REDO_BYTES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p749420514309"><a name="p749420514309"></a><a name="p749420514309"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1494950301"><a name="p1494950301"></a><a name="p1494950301"></a>待REDO操作的字节数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13172058145517"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19494185113018"><a name="p19494185113018"></a><a name="p19494185113018"></a>COMMITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p649455163019"><a name="p649455163019"></a><a name="p649455163019"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p64948511303"><a name="p64948511303"></a><a name="p64948511303"></a>提交次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row917558145510"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19494758307"><a name="p19494758307"></a><a name="p19494758307"></a>NOWAIT_COMMITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1949475143017"><a name="p1949475143017"></a><a name="p1949475143017"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12494857308"><a name="p12494857308"></a><a name="p12494857308"></a>NOWAIT模式提交次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row517135865511"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p44945515303"><a name="p44945515303"></a><a name="p44945515303"></a>XA_COMMITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124941556309"><a name="p124941556309"></a><a name="p124941556309"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p749416513303"><a name="p749416513303"></a><a name="p749416513303"></a>两阶段事务提交次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row217258155519"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p24951510309"><a name="p24951510309"></a><a name="p24951510309"></a>ROLLBACKS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p849525143011"><a name="p849525143011"></a><a name="p849525143011"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p154951553014"><a name="p154951553014"></a><a name="p154951553014"></a>回归次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row151665845518"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p54951156303"><a name="p54951156303"></a><a name="p54951156303"></a>XA_ROLLBACKS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14956517305"><a name="p14956517305"></a><a name="p14956517305"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p3495653304"><a name="p3495653304"></a><a name="p3495653304"></a>两阶段事务回滚次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9167585553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p94959518303"><a name="p94959518303"></a><a name="p94959518303"></a>LOCAL_TXN_TIMES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p84959533020"><a name="p84959533020"></a><a name="p84959533020"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6495155153015"><a name="p6495155153015"></a><a name="p6495155153015"></a>本地事务执行时间。（单位：微秒）</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11619586558"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p184951351304"><a name="p184951351304"></a><a name="p184951351304"></a>XA_TXN_TIMES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p204959515309"><a name="p204959515309"></a><a name="p204959515309"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p204956503014"><a name="p204956503014"></a><a name="p204956503014"></a>两阶段事务执行时间。（单位：微秒）</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row6161758195518"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p10495145123017"><a name="p10495145123017"></a><a name="p10495145123017"></a>PARSES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p64958553015"><a name="p64958553015"></a><a name="p64958553015"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p19495059308"><a name="p19495059308"></a><a name="p19495059308"></a>解析数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11163587555"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p14951454306"><a name="p14951454306"></a><a name="p14951454306"></a>HARD_PARSES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p174950503015"><a name="p174950503015"></a><a name="p174950503015"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p54955512306"><a name="p54955512306"></a><a name="p54955512306"></a>硬解析数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row91617583559"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1495105143013"><a name="p1495105143013"></a><a name="p1495105143013"></a>EVENT#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124953513308"><a name="p124953513308"></a><a name="p124953513308"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p04959517301"><a name="p04959517301"></a><a name="p04959517301"></a>事件号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18166588551"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2495154307"><a name="p2495154307"></a><a name="p2495154307"></a>EVENT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p144951651303"><a name="p144951651303"></a><a name="p144951651303"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1449511593017"><a name="p1449511593017"></a><a name="p1449511593017"></a>事件名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row171605817553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p3495185113014"><a name="p3495185113014"></a><a name="p3495185113014"></a>SORTS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4495185183018"><a name="p4495185183018"></a><a name="p4495185183018"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p949511514306"><a name="p949511514306"></a><a name="p949511514306"></a>当前会话累计统计排序次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row10161858185518"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19495185183013"><a name="p19495185183013"></a><a name="p19495185183013"></a>PROCESSED_ROWS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p44958519308"><a name="p44958519308"></a><a name="p44958519308"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1495165113018"><a name="p1495165113018"></a><a name="p1495165113018"></a>当前会话累计统计处理行。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row416658125510"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p24963517306"><a name="p24963517306"></a><a name="p24963517306"></a>IO_WAIT_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p194966513012"><a name="p194966513012"></a><a name="p194966513012"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p3496105103020"><a name="p3496105103020"></a><a name="p3496105103020"></a>当前会话累计统计SQL语句IO等待时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row91685811557"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p5496195153015"><a name="p5496195153015"></a><a name="p5496195153015"></a>CON_WAIT_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14961153303"><a name="p14961153303"></a><a name="p14961153303"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p64961054308"><a name="p64961054308"></a><a name="p64961054308"></a>当前会话累计统计SQL语句锁等待时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row21605817558"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p4496195143012"><a name="p4496195143012"></a><a name="p4496195143012"></a>CPU_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2496754304"><a name="p2496754304"></a><a name="p2496754304"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1496115133014"><a name="p1496115133014"></a><a name="p1496115133014"></a>当前会话累计统计SQL语句CPU占用时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1216125818559"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1549620511301"><a name="p1549620511301"></a><a name="p1549620511301"></a>ELAPSED_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1949615523020"><a name="p1949615523020"></a><a name="p1949615523020"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p94966563015"><a name="p94966563015"></a><a name="p94966563015"></a>当前会话累计统计SQL语句的总耗时（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1116115813550"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p54967514305"><a name="p54967514305"></a><a name="p54967514305"></a>ISOLEVEL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19496115123012"><a name="p19496115123012"></a><a name="p19496115123012"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p249619512308"><a name="p249619512308"></a><a name="p249619512308"></a>会话的事务隔离级别：</p>
<a name="ul13949105083915"></a><a name="ul13949105083915"></a><ul id="ul13949105083915"><li>1：read committed</li><li>2：current committed</li><li>3：serializable</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row416155818553"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p144967543010"><a name="p144967543010"></a><a name="p144967543010"></a>MODULE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p849615173013"><a name="p849615173013"></a><a name="p849615173013"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p14966533019"><a name="p14966533019"></a><a name="p14966533019"></a>第一次硬解析该SQL时，执行它的客户端名称。目前可能的值为GSC_APPLICATION， JDBC，ZSQL。对于不识别的客户端，显示为UNKNOWN。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row91655815556"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p114961518307"><a name="p114961518307"></a><a name="p114961518307"></a>VMP_PAGES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p124961456302"><a name="p124961456302"></a><a name="p124961456302"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6496853304"><a name="p6496853304"></a><a name="p6496853304"></a>VMP从VMA上已申请的内存页数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row31611582556"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p134967519305"><a name="p134967519305"></a><a name="p134967519305"></a>LARGE_VMP_PAGES</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p12496358306"><a name="p12496358306"></a><a name="p12496358306"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p64967523017"><a name="p64967523017"></a><a name="p64967523017"></a>LARGE VMP从LARGE VMA上已申请的内存页数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row116185815520"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p184961533015"><a name="p184961533015"></a><a name="p184961533015"></a>RES_CONTROL_GROUP</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p84969583018"><a name="p84969583018"></a><a name="p84969583018"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p569116358402"><a name="p569116358402"></a><a name="p569116358402"></a>资源组名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row12161458125514"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1497205123016"><a name="p1497205123016"></a><a name="p1497205123016"></a>RES_IO_WAIT_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1949711516306"><a name="p1949711516306"></a><a name="p1949711516306"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1369015357406"><a name="p1369015357406"></a><a name="p1369015357406"></a>资源IO等待时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row151685820557"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1949719573016"><a name="p1949719573016"></a><a name="p1949719573016"></a>RES_QUEUE_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p16497954302"><a name="p16497954302"></a><a name="p16497954302"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p469020356405"><a name="p469020356405"></a><a name="p469020356405"></a>资源会话排队时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13161058155518"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p15497956306"><a name="p15497956306"></a><a name="p15497956306"></a>PRIV_FLAG</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p84978510305"><a name="p84978510305"></a><a name="p84978510305"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p7690153513403"><a name="p7690153513403"></a><a name="p7690153513403"></a>当前会话是否为private。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row916958145511"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p124979511305"><a name="p124979511305"></a><a name="p124979511305"></a>QUERY_SCN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1849718519301"><a name="p1849718519301"></a><a name="p1849718519301"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p96904354404"><a name="p96904354404"></a><a name="p96904354404"></a>当前的query_scn。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1516158185517"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p16497175163012"><a name="p16497175163012"></a><a name="p16497175163012"></a>STMT_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p134973514305"><a name="p134973514305"></a><a name="p134973514305"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p186891735184016"><a name="p186891735184016"></a><a name="p186891735184016"></a>sql句柄数量。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9167588551"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p449717516305"><a name="p449717516305"></a><a name="p449717516305"></a>MIN_SCN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14497205113013"><a name="p14497205113013"></a><a name="p14497205113013"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p168933518400"><a name="p168933518400"></a><a name="p168933518400"></a>当前会话的最小scn。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row71619583550"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1049718513020"><a name="p1049718513020"></a><a name="p1049718513020"></a>PREV_SQL_ID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1449745173018"><a name="p1449745173018"></a><a name="p1449745173018"></a>VARCHAR(10)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1668916352406"><a name="p1668916352406"></a><a name="p1668916352406"></a>当前会话前一个sql_id。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row116195813559"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p11497555307"><a name="p11497555307"></a><a name="p11497555307"></a>DCS_BUFFER_GETS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p114975516308"><a name="p114975516308"></a><a name="p114975516308"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p46891135164019"><a name="p46891135164019"></a><a name="p46891135164019"></a>通过DCS进行缓存读取的次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row181665885514"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p349715515308"><a name="p349715515308"></a><a name="p349715515308"></a>DCS_BUFFER_SENDS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p249755113015"><a name="p249755113015"></a><a name="p249755113015"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p768853513403"><a name="p768853513403"></a><a name="p768853513403"></a>通过DCS发送缓存页面的次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row816175815513"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1349711583019"><a name="p1349711583019"></a><a name="p1349711583019"></a>DCS_CR_GETS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p11497125183018"><a name="p11497125183018"></a><a name="p11497125183018"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p156885355401"><a name="p156885355401"></a><a name="p156885355401"></a>事务并发场景下，SQL语句在CR POOL中查找的次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row316175818559"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1349813573017"><a name="p1349813573017"></a><a name="p1349813573017"></a>DCS_CR_SENDS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p154980516308"><a name="p154980516308"></a><a name="p154980516308"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6668193514012"><a name="p6668193514012"></a><a name="p6668193514012"></a>事务并发场景下，SQL语句在CR POOL中发送的次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row3403714111418"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p53421440182918"><a name="p53421440182918"></a><a name="p53421440182918"></a>cantian.dv_segment_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p1861810137224"><a name="p1861810137224"></a><a name="p1861810137224"></a>查看当前数据库的各类事件等待情况。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9646134631517"><td class="cellrowborder" rowspan="8" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="8" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p14619181318223"><a name="p14619181318223"></a><a name="p14619181318223"></a>OWNER</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p3619131322213"><a name="p3619131322213"></a><a name="p3619131322213"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p1561981318221"><a name="p1561981318221"></a><a name="p1561981318221"></a>对象的所有者名称。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row47101348161514"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p14619131382213"><a name="p14619131382213"></a><a name="p14619131382213"></a>OBJECT_NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p361921318229"><a name="p361921318229"></a><a name="p361921318229"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p661961311223"><a name="p661961311223"></a><a name="p661961311223"></a>对象名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row656355010155"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p16619171312217"><a name="p16619171312217"></a><a name="p16619171312217"></a>SUBOBJECT_NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p46194134223"><a name="p46194134223"></a><a name="p46194134223"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1461981315227"><a name="p1461981315227"></a><a name="p1461981315227"></a>子对象名称，如分区名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row14945195214154"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p8619161392216"><a name="p8619161392216"></a><a name="p8619161392216"></a>TS#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p96199137224"><a name="p96199137224"></a><a name="p96199137224"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p661911322217"><a name="p661911322217"></a><a name="p661911322217"></a>所在表空间序号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2051605451519"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p361961312221"><a name="p361961312221"></a><a name="p361961312221"></a>OBJECT_TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4619131320224"><a name="p4619131320224"></a><a name="p4619131320224"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p26191513162215"><a name="p26191513162215"></a><a name="p26191513162215"></a>对象的类型，如表，索引。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16186175612155"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p76191413162218"><a name="p76191413162218"></a><a name="p76191413162218"></a>STATISTIC_NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p161921312226"><a name="p161921312226"></a><a name="p161921312226"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p961921319222"><a name="p961921319222"></a><a name="p961921319222"></a>统计信息类型。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row0431858161513"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p196191013122217"><a name="p196191013122217"></a><a name="p196191013122217"></a>STATISTIC#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p126194138226"><a name="p126194138226"></a><a name="p126194138226"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6619201322219"><a name="p6619201322219"></a><a name="p6619201322219"></a>统计信息序号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row495419597151"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p14619713112211"><a name="p14619713112211"></a><a name="p14619713112211"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p136191513152218"><a name="p136191513152218"></a><a name="p136191513152218"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17619201352213"><a name="p17619201352213"></a><a name="p17619201352213"></a>统计值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row116875249168"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p2647205591810"><a name="p2647205591810"></a><a name="p2647205591810"></a>cantian.dv_session_events</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p114631022214"><a name="p114631022214"></a><a name="p114631022214"></a><span>查询会话的所有的等待事件的统计信息</span>。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row37791126191620"><td class="cellrowborder" rowspan="11" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="11" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p136331021172512"><a name="p136331021172512"></a><a name="p136331021172512"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p18633102116252"><a name="p18633102116252"></a><a name="p18633102116252"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p563316219255"><a name="p563316219255"></a><a name="p563316219255"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row162281749171613"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p0633172152513"><a name="p0633172152513"></a><a name="p0633172152513"></a>EVENT#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14633192119254"><a name="p14633192119254"></a><a name="p14633192119254"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p16633172192512"><a name="p16633172192512"></a><a name="p16633172192512"></a>事件号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row12232151101614"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1633192118255"><a name="p1633192118255"></a><a name="p1633192118255"></a>EVENT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p8633142132513"><a name="p8633142132513"></a><a name="p8633142132513"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10633621162515"><a name="p10633621162515"></a><a name="p10633621162515"></a>事件名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row6755553151619"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p176331021112518"><a name="p176331021112518"></a><a name="p176331021112518"></a>P1</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p7633172114256"><a name="p7633172114256"></a><a name="p7633172114256"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p86331121162513"><a name="p86331121162513"></a><a name="p86331121162513"></a>附加参数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1771355511611"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1363311211256"><a name="p1363311211256"></a><a name="p1363311211256"></a>WAIT_CLASS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1963312212257"><a name="p1963312212257"></a><a name="p1963312212257"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p86336218258"><a name="p86336218258"></a><a name="p86336218258"></a>事件所属类名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row166519578163"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1963320215259"><a name="p1963320215259"></a><a name="p1963320215259"></a>TOTAL_WAITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p116333216255"><a name="p116333216255"></a><a name="p116333216255"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p9633192182516"><a name="p9633192182516"></a><a name="p9633192182516"></a>事件等待次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row014114016172"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1063310210251"><a name="p1063310210251"></a><a name="p1063310210251"></a>TIME_WAITED</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p16332219259"><a name="p16332219259"></a><a name="p16332219259"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1633102120253"><a name="p1633102120253"></a><a name="p1633102120253"></a>事件已经等待时间（单位：秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row517515210177"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p17777151417274"><a name="p17777151417274"></a><a name="p17777151417274"></a>TIME_WAITED_MIRCO</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p27771414102711"><a name="p27771414102711"></a><a name="p27771414102711"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p8777181416276"><a name="p8777181416276"></a><a name="p8777181416276"></a>事件已经等待时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row174158411179"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p04064369216"><a name="p04064369216"></a><a name="p04064369216"></a>AVERAGE_WAIT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1640623672116"><a name="p1640623672116"></a><a name="p1640623672116"></a>BINARY_DOUBLE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1240583618216"><a name="p1240583618216"></a><a name="p1240583618216"></a>事件已经等待平均时间（单位：秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1196216612176"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p11405113612116"><a name="p11405113612116"></a><a name="p11405113612116"></a>AVERAGE_WAIT_MIRCO</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1040523610215"><a name="p1040523610215"></a><a name="p1040523610215"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p114051363215"><a name="p114051363215"></a><a name="p114051363215"></a>事件已经等待平均时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row12542179151716"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p3405163610211"><a name="p3405163610211"></a><a name="p3405163610211"></a>TENANT_ID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1840553652113"><a name="p1840553652113"></a><a name="p1840553652113"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p04041536112112"><a name="p04041536112112"></a><a name="p04041536112112"></a>租户id。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1822316186181"><td class="cellrowborder" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 "><p id="p666444821714"><a name="p666444821714"></a><a name="p666444821714"></a>cantian.dv_sys_events</p>
</td>
<td class="cellrowborder" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 "><p id="p9664748111712"><a name="p9664748111712"></a><a name="p9664748111712"></a>查询系统的基础统计，包括sql执行情况，读写盘时延等信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1473742061812"><td class="cellrowborder" rowspan="4" valign="top" width="17.391739173917394%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="4" valign="top" width="27.14271427142714%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1466494871719"><a name="p1466494871719"></a><a name="p1466494871719"></a>STATISTIC#</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p18664548151717"><a name="p18664548151717"></a><a name="p18664548151717"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p16664748191717"><a name="p16664748191717"></a><a name="p16664748191717"></a>统计项编号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18912152261818"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p106641248141713"><a name="p106641248141713"></a><a name="p106641248141713"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p76649488174"><a name="p76649488174"></a><a name="p76649488174"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1966424811717"><a name="p1966424811717"></a><a name="p1966424811717"></a>统计项名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row149805394184"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1966414820174"><a name="p1966414820174"></a><a name="p1966414820174"></a>CLASS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1664194812176"><a name="p1664194812176"></a><a name="p1664194812176"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p116642481178"><a name="p116642481178"></a><a name="p116642481178"></a>统计类型：</p>
<a name="ul19211518436"></a><a name="ul19211518436"></a><ul id="ul19211518436"><li>0：SQL类型</li><li>1：Kernel类型</li><li>2：Instance类型</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row3645124231815"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p766519489172"><a name="p766519489172"></a><a name="p766519489172"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4665164814179"><a name="p4665164814179"></a><a name="p4665164814179"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p66653487171"><a name="p66653487171"></a><a name="p66653487171"></a>统计项值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

其中，cantian.dv\_session\_events表的每行数据都对应一种等待事件，等待事件共分7大类：

<a name="table1972135163413"></a>
<table><tbody><tr id="row8721205115343"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p475418335011"><a name="p475418335011"></a><a name="p475418335011"></a>1</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p16721105103411"><a name="p16721105103411"></a><a name="p16721105103411"></a>IDLE：意味会话没有等待时间或者等待着工作。</p>
</td>
</tr>
<tr id="row15721751153413"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p18754034506"><a name="p18754034506"></a><a name="p18754034506"></a>2</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p10722851193411"><a name="p10722851193411"></a><a name="p10722851193411"></a>concurrency：由数据库的内部资源争抢引起的。</p>
</td>
</tr>
<tr id="row1722105113343"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p575412325017"><a name="p575412325017"></a><a name="p575412325017"></a>3</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p147221851113419"><a name="p147221851113419"></a><a name="p147221851113419"></a>application：由于用户的业务语句引起的资源争抢。</p>
</td>
</tr>
<tr id="row57221951113420"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p575493135012"><a name="p575493135012"></a><a name="p575493135012"></a>4</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p1722051193412"><a name="p1722051193412"></a><a name="p1722051193412"></a>User/IO：由用户业务语句引起的I/O操作。</p>
</td>
</tr>
<tr id="row1172218517344"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p1754438504"><a name="p1754438504"></a><a name="p1754438504"></a>5</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p1772245143410"><a name="p1772245143410"></a><a name="p1772245143410"></a>configuration：由于数据库的配置不当引起的等待。</p>
</td>
</tr>
<tr id="row11722451143413"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p167543335019"><a name="p167543335019"></a><a name="p167543335019"></a>6</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p1972255113346"><a name="p1972255113346"></a><a name="p1972255113346"></a>commit：等待commit完成。</p>
</td>
</tr>
<tr id="row472205193420"><td class="cellrowborder" valign="top" width="7.5200000000000005%"><p id="p77546311504"><a name="p77546311504"></a><a name="p77546311504"></a>7</p>
</td>
<td class="cellrowborder" valign="top" width="92.47999999999999%"><p id="p207221351153414"><a name="p207221351153414"></a><a name="p207221351153414"></a>other：其他。</p>
</td>
</tr>
</tbody>
</table>

每种等待事件具体含义如下：

<a name="table820272220209"></a>
<table><thead align="left"><tr id="row540745072011"><th class="cellrowborder" valign="top" width="52.23%" id="mcps1.1.3.1.1"><p id="p440765032015"><a name="p440765032015"></a><a name="p440765032015"></a>等待事件</p>
</th>
<th class="cellrowborder" valign="top" width="47.77%" id="mcps1.1.3.1.2"><p id="p640765092020"><a name="p640765092020"></a><a name="p640765092020"></a>等待事件产生的原因</p>
</th>
</tr>
</thead>
<tbody><tr id="row320312216200"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p42031322142010"><a name="p42031322142010"></a><a name="p42031322142010"></a>idle wait</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p4203112292016"><a name="p4203112292016"></a><a name="p4203112292016"></a>会话属于空闲等待状态。</p>
</td>
</tr>
<tr id="row4203192262020"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p32035223208"><a name="p32035223208"></a><a name="p32035223208"></a>message from client</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p420312222203"><a name="p420312222203"></a><a name="p420312222203"></a>会话没有执行语句，等待接收客户端的指令。</p>
</td>
</tr>
<tr id="row62037223205"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p4203202252013"><a name="p4203202252013"></a><a name="p4203202252013"></a>message to client</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p3203102219205"><a name="p3203102219205"></a><a name="p3203102219205"></a>暂未使用。</p>
</td>
</tr>
<tr id="row16203022112012"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p9203822162011"><a name="p9203822162011"></a><a name="p9203822162011"></a>latch: large pool</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p12039228204"><a name="p12039228204"></a><a name="p12039228204"></a>large pool 分配内存。</p>
</td>
</tr>
<tr id="row112038224206"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p0203202232011"><a name="p0203202232011"></a><a name="p0203202232011"></a>latch: data buffer pool</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p2203122102011"><a name="p2203122102011"></a><a name="p2203122102011"></a>data buffer pool 分配内存。</p>
</td>
</tr>
<tr id="row1120322213206"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1920342219205"><a name="p1920342219205"></a><a name="p1920342219205"></a>latch: cache buffers chains</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p10203132215202"><a name="p10203132215202"></a><a name="p10203132215202"></a>暂未使用。</p>
</td>
</tr>
<tr id="row112031422132020"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p3203102272010"><a name="p3203102272010"></a><a name="p3203102272010"></a>cursor: mutex</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p52031122142014"><a name="p52031122142014"></a><a name="p52031122142014"></a>暂未使用。</p>
</td>
</tr>
<tr id="row1320310221207"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p172037223207"><a name="p172037223207"></a><a name="p172037223207"></a>library : mutex</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p120320222204"><a name="p120320222204"></a><a name="p120320222204"></a>用于存储过程的entry加锁。</p>
</td>
</tr>
<tr id="row8203142232011"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p12203182262017"><a name="p12203182262017"></a><a name="p12203182262017"></a>log file sync</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1920322262020"><a name="p1920322262020"></a><a name="p1920322262020"></a>正在commit，等待commit结束。</p>
</td>
</tr>
<tr id="row720316224204"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p720322282014"><a name="p720322282014"></a><a name="p720322282014"></a>buffer busy waits</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p3203102242015"><a name="p3203102242015"></a><a name="p3203102242015"></a>当一个会话需要去修改页面时被阻塞。</p>
</td>
</tr>
<tr id="row420316228203"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p12036222205"><a name="p12036222205"></a><a name="p12036222205"></a>enq: TX row lock contention</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1320322212017"><a name="p1320322212017"></a><a name="p1320322212017"></a>会话在表heap上发生行锁等待。</p>
</td>
</tr>
<tr id="row1120322242013"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p120392217203"><a name="p120392217203"></a><a name="p120392217203"></a>enq: TX alloc itl entry</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1820462217204"><a name="p1820462217204"></a><a name="p1820462217204"></a>会话在申请ITL时发生等待。</p>
</td>
</tr>
<tr id="row9204132212011"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p18204162211206"><a name="p18204162211206"></a><a name="p18204162211206"></a>enq: TX index contention</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p142049227203"><a name="p142049227203"></a><a name="p142049227203"></a>会话在索引上发生行锁等待。</p>
</td>
</tr>
<tr id="row1520492214203"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p14204192220205"><a name="p14204192220205"></a><a name="p14204192220205"></a>enq: TX table lock S</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p5204102220202"><a name="p5204102220202"></a><a name="p5204102220202"></a>会话发生表锁等待，需要加S锁。</p>
</td>
</tr>
<tr id="row52042223207"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1120412214208"><a name="p1120412214208"></a><a name="p1120412214208"></a>enq: TX table lock X</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p102041322122014"><a name="p102041322122014"></a><a name="p102041322122014"></a>会话发生表锁等待，需要加X锁。</p>
</td>
</tr>
<tr id="row920482292015"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p820417222206"><a name="p820417222206"></a><a name="p820417222206"></a>enq: TX read  wait</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p9204122282012"><a name="p9204122282012"></a><a name="p9204122282012"></a>事务读请求产生的等待。</p>
</td>
</tr>
<tr id="row12204182210203"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p220442292010"><a name="p220442292010"></a><a name="p220442292010"></a>db file scattered read</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p12204922142014"><a name="p12204922142014"></a><a name="p12204922142014"></a>每次I/O需要读取多个heap页面的SQL，会产生这个等待时间，最常见与全表扫描。</p>
</td>
</tr>
<tr id="row820462292015"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p11204162214200"><a name="p11204162214200"></a><a name="p11204162214200"></a>db file sequential read</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p192041222122012"><a name="p192041222122012"></a><a name="p192041222122012"></a>每次I/O需要读取一个索引页面或者通过索引读取一个heap页面，最常见于索引扫描。</p>
</td>
</tr>
<tr id="row10204522192018"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p2204132214202"><a name="p2204132214202"></a><a name="p2204132214202"></a>db file gbp read</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p192048228209"><a name="p192048228209"></a><a name="p192048228209"></a>暂未使用。</p>
</td>
</tr>
<tr id="row920415229202"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p6204102216203"><a name="p6204102216203"></a><a name="p6204102216203"></a>mtrl segment sort</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p4204112272019"><a name="p4204112272019"></a><a name="p4204112272019"></a>新创建一个表，产生索引，索引的页面发生排序产生的等待。</p>
</td>
</tr>
<tr id="row1204202216205"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p620414225207"><a name="p620414225207"></a><a name="p620414225207"></a>log file switch(checkpoint incomplete)</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1420442216208"><a name="p1420442216208"></a><a name="p1420442216208"></a>redo日志追尾，需要等待checkpoint。</p>
</td>
</tr>
<tr id="row62047221208"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1220492213209"><a name="p1220492213209"></a><a name="p1220492213209"></a>log file switch(archiving needed)</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p13204122262015"><a name="p13204122262015"></a><a name="p13204122262015"></a>redo日志追尾，需要等待归档。</p>
</td>
</tr>
<tr id="row62040226201"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p520402202015"><a name="p520402202015"></a><a name="p520402202015"></a>read by other session</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p420413226203"><a name="p420413226203"></a><a name="p420413226203"></a>需要访问的页面正在被其他session加载上来。</p>
</td>
</tr>
<tr id="row620432213201"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p17204122112013"><a name="p17204122112013"></a><a name="p17204122112013"></a>attached to agent</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p13204722192015"><a name="p13204722192015"></a><a name="p13204722192015"></a>给会话绑定agent。</p>
</td>
</tr>
<tr id="row3204222202015"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p62045227204"><a name="p62045227204"></a><a name="p62045227204"></a>heap find map</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p7204222182017"><a name="p7204222182017"></a><a name="p7204222182017"></a>查找空闲页面。</p>
</td>
</tr>
<tr id="row1520432212018"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1620418226204"><a name="p1620418226204"></a><a name="p1620418226204"></a>heap extend segment</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p18204162215204"><a name="p18204162215204"></a><a name="p18204162215204"></a>表在扩展segment,一般发生在insert。</p>
</td>
</tr>
<tr id="row10204102212016"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p920462232010"><a name="p920462232010"></a><a name="p920462232010"></a>resmgr: io quantum</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p152041522192012"><a name="p152041522192012"></a><a name="p152041522192012"></a>暂未使用。</p>
</td>
</tr>
<tr id="row42042229206"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p420412229202"><a name="p420412229202"></a><a name="p420412229202"></a>direct path read temp</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p182041122112011"><a name="p182041122112011"></a><a name="p182041122112011"></a>一般是内存temp buff不够引起的等待。</p>
</td>
</tr>
<tr id="row19204022112019"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p7204132272014"><a name="p7204132272014"></a><a name="p7204132272014"></a>direct path write temp</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p12204122202013"><a name="p12204122202013"></a><a name="p12204122202013"></a>写临时表空间产生的等待。</p>
</td>
</tr>
<tr id="row1620416225209"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p620417221201"><a name="p620417221201"></a><a name="p620417221201"></a>advisory lock wait time</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1320592210203"><a name="p1320592210203"></a><a name="p1320592210203"></a>咨询锁加锁发生锁等待。</p>
</td>
</tr>
<tr id="row8205192210204"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p120542272017"><a name="p120542272017"></a><a name="p120542272017"></a>cn commit</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1220512213204"><a name="p1220512213204"></a><a name="p1220512213204"></a>暂未使用。</p>
</td>
</tr>
<tr id="row62050226204"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1820512292018"><a name="p1820512292018"></a><a name="p1820512292018"></a>cn execute request</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p22051722132017"><a name="p22051722132017"></a><a name="p22051722132017"></a>暂未使用。</p>
</td>
</tr>
<tr id="row16205142282018"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1520542212209"><a name="p1520542212209"></a><a name="p1520542212209"></a>cn execute ack</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p220562215206"><a name="p220562215206"></a><a name="p220562215206"></a>暂未使用。</p>
</td>
</tr>
<tr id="row12205152216203"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p2020510223202"><a name="p2020510223202"></a><a name="p2020510223202"></a>buf enter temp page with nolock</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p52059225204"><a name="p52059225204"></a><a name="p52059225204"></a>访问临时表page产生的等待。</p>
</td>
</tr>
<tr id="row122059224208"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1120515224204"><a name="p1120515224204"></a><a name="p1120515224204"></a>online redo log recycle</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p420572219201"><a name="p420572219201"></a><a name="p420572219201"></a>redo日志回收产生的等待。</p>
</td>
</tr>
<tr id="row12205162219201"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p420582214206"><a name="p420582214206"></a><a name="p420582214206"></a>undo alloc page from space</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p102051422182012"><a name="p102051422182012"></a><a name="p102051422182012"></a>undo空间扩展产生的等待。</p>
</td>
</tr>
<tr id="row9205112216205"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p020502272012"><a name="p020502272012"></a><a name="p020502272012"></a>plsql object lock wait</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p320510227202"><a name="p320510227202"></a><a name="p320510227202"></a>plsql加锁产生的等待。</p>
</td>
</tr>
<tr id="row22058227203"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p4205142292010"><a name="p4205142292010"></a><a name="p4205142292010"></a>latch: temp pool</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p16205112215203"><a name="p16205112215203"></a><a name="p16205112215203"></a>暂未使用。</p>
</td>
</tr>
<tr id="row11205102211205"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p72057229209"><a name="p72057229209"></a><a name="p72057229209"></a>parallel finish</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p9205162272019"><a name="p9205162272019"></a><a name="p9205162272019"></a>暂未使用。</p>
</td>
</tr>
<tr id="row13205922152010"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p11205122292014"><a name="p11205122292014"></a><a name="p11205122292014"></a>gc buffer busy</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p52051322142020"><a name="p52051322142020"></a><a name="p52051322142020"></a>会话需要访问的buffer正在被另一个会话使用产生的等待。</p>
</td>
</tr>
<tr id="row12205222132014"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1920516228202"><a name="p1920516228202"></a><a name="p1920516228202"></a>dcs: request master4page 1-way</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p32051224208"><a name="p32051224208"></a><a name="p32051224208"></a>请求page时，page master和owner在本地产生的等待。</p>
</td>
</tr>
<tr id="row14205622192017"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p172055222201"><a name="p172055222201"></a><a name="p172055222201"></a>dcs: request master4page 2-way</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p720592217201"><a name="p720592217201"></a><a name="p720592217201"></a>请求page时，page master在远端，owner在本地产生的等待。</p>
</td>
</tr>
<tr id="row13205102212013"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p14205022172013"><a name="p14205022172013"></a><a name="p14205022172013"></a>dcs: request master4page 3-way</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p102055220208"><a name="p102055220208"></a><a name="p102055220208"></a>请求page时，master和owner都不在一个节点上，owner在远端产生的等待。</p>
</td>
</tr>
<tr id="row920510226204"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1120592232017"><a name="p1120592232017"></a><a name="p1120592232017"></a>dcs: request master4page try</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1320582219200"><a name="p1320582219200"></a><a name="p1320582219200"></a>向master请求对page加S锁时产生的等待。</p>
</td>
</tr>
<tr id="row162051222122019"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p320512212209"><a name="p320512212209"></a><a name="p320512212209"></a>dcs: request owner4page</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p8205142214203"><a name="p8205142214203"></a><a name="p8205142214203"></a>向owner请求page产生的等待。</p>
</td>
</tr>
<tr id="row192051822122016"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p7205182282019"><a name="p7205182282019"></a><a name="p7205182282019"></a>dcs: claim owner</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p142051622152012"><a name="p142051622152012"></a><a name="p142051622152012"></a>暂未使用。</p>
</td>
</tr>
<tr id="row4205722152011"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p720572219206"><a name="p720572219206"></a><a name="p720572219206"></a>dcs: recycle owner</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p52061622122015"><a name="p52061622122015"></a><a name="p52061622122015"></a>失效page owner时产生的等待。</p>
</td>
</tr>
<tr id="row72061622182020"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p11206322182012"><a name="p11206322182012"></a><a name="p11206322182012"></a>dcs: invalidate readonly copy</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1620620229203"><a name="p1620620229203"></a><a name="p1620620229203"></a>失效只读副本时产生的等待。</p>
</td>
</tr>
<tr id="row162061222132019"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p520642217202"><a name="p520642217202"></a><a name="p520642217202"></a>dcs: invalidate readonly copy process</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p920622272012"><a name="p920622272012"></a><a name="p920622272012"></a>处理只读副本失效产生的等待。</p>
</td>
</tr>
<tr id="row1720662242015"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1120632222011"><a name="p1120632222011"></a><a name="p1120632222011"></a>dcs: transfer page latch</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p172061822152013"><a name="p172061822152013"></a><a name="p172061822152013"></a>暂未使用。</p>
</td>
</tr>
<tr id="row1720615221201"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p182061322182010"><a name="p182061322182010"></a><a name="p182061322182010"></a>dcs: transfer page readonly2x</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p142065222200"><a name="p142065222200"></a><a name="p142065222200"></a>暂未使用。</p>
</td>
</tr>
<tr id="row102061822182013"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p102069226207"><a name="p102069226207"></a><a name="p102069226207"></a>dcs: transfer page flush log</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p19206102252011"><a name="p19206102252011"></a><a name="p19206102252011"></a>转发page前redo刷盘产生的等待。</p>
</td>
</tr>
<tr id="row192066224201"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p19206122182017"><a name="p19206122182017"></a><a name="p19206122182017"></a>dcs: transfer page</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p10206172218200"><a name="p10206172218200"></a><a name="p10206172218200"></a>转发page时产生的等待。</p>
</td>
</tr>
<tr id="row320642214204"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1620617225201"><a name="p1620617225201"></a><a name="p1620617225201"></a>dcs: transfer last edp page</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p420632242012"><a name="p420632242012"></a><a name="p420632242012"></a>暂未使用。</p>
</td>
</tr>
<tr id="row220622214205"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p82061922132018"><a name="p82061922132018"></a><a name="p82061922132018"></a>dcs: transfer last edp page latch</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p15206822202014"><a name="p15206822202014"></a><a name="p15206822202014"></a>暂未使用。</p>
</td>
</tr>
<tr id="row1820612224201"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p920652262018"><a name="p920652262018"></a><a name="p920652262018"></a>pcr: request btree page</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p32061122112017"><a name="p32061122112017"></a><a name="p32061122112017"></a>构造btree CRpage产生的等待。</p>
</td>
</tr>
<tr id="row1720622202012"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p112061822172017"><a name="p112061822172017"></a><a name="p112061822172017"></a>pcr: request heap page</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p192067225205"><a name="p192067225205"></a><a name="p192067225205"></a>构造heap CRpage产生的等待。</p>
</td>
</tr>
<tr id="row1620602262012"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p16206122216209"><a name="p16206122216209"></a><a name="p16206122216209"></a>pcr: request master</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p102061223204"><a name="p102061223204"></a><a name="p102061223204"></a>向master请求CR page产生的等待。</p>
</td>
</tr>
<tr id="row1620618223209"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p132062224206"><a name="p132062224206"></a><a name="p132062224206"></a>pcr: request owner</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p120612202017"><a name="p120612202017"></a><a name="p120612202017"></a>向owner请求CR page产生的等待。</p>
</td>
</tr>
<tr id="row182061322142012"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1520682211203"><a name="p1520682211203"></a><a name="p1520682211203"></a>pcr: check current visible</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p192061622172015"><a name="p192061622172015"></a><a name="p192061622172015"></a>检查当前row是否可见时产生的等待。</p>
</td>
</tr>
<tr id="row19206222112010"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p112063224209"><a name="p112063224209"></a><a name="p112063224209"></a>txn: request txn info</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p020611221206"><a name="p020611221206"></a><a name="p020611221206"></a>向其他节点请求事务信息时产生的等待。</p>
</td>
</tr>
<tr id="row20206922112015"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1620652272017"><a name="p1620652272017"></a><a name="p1620652272017"></a>txn: request txn snapshot</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p17206112212202"><a name="p17206112212202"></a><a name="p17206112212202"></a>向其他节点请求事务快照信息时产生的等待。</p>
</td>
</tr>
<tr id="row18206202222019"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p12206132211205"><a name="p12206132211205"></a><a name="p12206132211205"></a>dls: request spinlock/latch</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p920611227202"><a name="p920611227202"></a><a name="p920611227202"></a>dls向其他节点请求锁信息时产生的等待。</p>
</td>
</tr>
<tr id="row32061722192015"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1120619225206"><a name="p1120619225206"></a><a name="p1120619225206"></a>dls: request table lock</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p15206142282017"><a name="p15206142282017"></a><a name="p15206142282017"></a>暂未使用。</p>
</td>
</tr>
<tr id="row1820615222205"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p19206142210201"><a name="p19206142210201"></a><a name="p19206142210201"></a>txn: wait remote</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1820692222015"><a name="p1820692222015"></a><a name="p1820692222015"></a>dls向其他节点请求事务信息时产生的等待。</p>
</td>
</tr>
<tr id="row02071722122019"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p520762262017"><a name="p520762262017"></a><a name="p520762262017"></a>smon: dead lock check txn remote</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p15207142216200"><a name="p15207142216200"></a><a name="p15207142216200"></a>做死锁检测，需要在远端看一下事务信息产生的等待。</p>
</td>
</tr>
<tr id="row720772262019"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p1120712232020"><a name="p1120712232020"></a><a name="p1120712232020"></a>smon: dead lock check table remote</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p172071022192018"><a name="p172071022192018"></a><a name="p172071022192018"></a>做死锁检测，需要在远端看一下表信息产生的等待。</p>
</td>
</tr>
<tr id="row18207142216202"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p320712217206"><a name="p320712217206"></a><a name="p320712217206"></a>smon: dead lock check itl remote</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p16207222172016"><a name="p16207222172016"></a><a name="p16207222172016"></a>做死锁检测，需要在远端看一下itl信息产生的等待。</p>
</td>
</tr>
<tr id="row1120712219207"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p920792282010"><a name="p920792282010"></a><a name="p920792282010"></a>broadcast btree split</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p82071522122018"><a name="p82071522122018"></a><a name="p82071522122018"></a>广播通知btree分裂产生的等待。</p>
</td>
</tr>
<tr id="row142073224208"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p720712211206"><a name="p720712211206"></a><a name="p720712211206"></a>broadcast btree root page</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p1720716229201"><a name="p1720716229201"></a><a name="p1720716229201"></a>btree分裂完广播root和page给其他节点产生的等待。</p>
</td>
</tr>
<tr id="row1620772272012"><td class="cellrowborder" valign="top" width="52.23%" headers="mcps1.1.3.1.1 "><p id="p2207172252016"><a name="p2207172252016"></a><a name="p2207172252016"></a>ckpt disable wait</p>
</td>
<td class="cellrowborder" valign="top" width="47.77%" headers="mcps1.1.3.1.2 "><p id="p920710229209"><a name="p920710229209"></a><a name="p920710229209"></a>执行ddl时，等待ckpt停住产生的用时。</p>
</td>
</tr>
</tbody>
</table>

# 锁等待信息<a name="ZH-CN_TOPIC_0000001819458874"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row128871417448"><th class="cellrowborder" valign="top" width="17.401740174017398%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b576384933617"><a name="b576384933617"></a><a name="b576384933617"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="27.13271327132713%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b37637497369"><a name="b37637497369"></a><a name="b37637497369"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="14.84148414841484%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b1476414983614"><a name="b1476414983614"></a><a name="b1476414983614"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="9.8009800980098%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b1176494915366"><a name="b1176494915366"></a><a name="b1176494915366"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="18.891889188918892%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b776594953614"><a name="b776594953614"></a><a name="b776594953614"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b1376554933611"><a name="b1376554933611"></a><a name="b1376554933611"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row25948301311"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p1981615539913"><a name="p1981615539913"></a><a name="p1981615539913"></a>cantian.dv_locks</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p14318151941015"><a name="p14318151941015"></a><a name="p14318151941015"></a><span>查看当前锁资源情况</span>。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row346645203013"><td class="cellrowborder" rowspan="7" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="7" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p323352113415"><a name="p323352113415"></a><a name="p323352113415"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1823312112415"><a name="p1823312112415"></a><a name="p1823312112415"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p18233112112417"><a name="p18233112112417"></a><a name="p18233112112417"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18466125203017"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p123392194118"><a name="p123392194118"></a><a name="p123392194118"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p102331821194115"><a name="p102331821194115"></a><a name="p102331821194115"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12330213414"><a name="p12330213414"></a><a name="p12330213414"></a>锁类型：TS/TX/RS/RX/KS/KX。目前使用TS/TX/RX/KX锁，其中TS/TX锁属于表级锁，RX/KX锁属于事务锁。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row7466115193019"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1223352116419"><a name="p1223352116419"></a><a name="p1223352116419"></a>ID1</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p923362118414"><a name="p923362118414"></a><a name="p923362118414"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1423332154117"><a name="p1423332154117"></a><a name="p1423332154117"></a>锁类型为TS/TX时，显示等待的DC对应用户ID；其他锁类型，显示正在获取的page编号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row164669513304"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p8233162144111"><a name="p8233162144111"></a><a name="p8233162144111"></a>ID2</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p523352110415"><a name="p523352110415"></a><a name="p523352110415"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17233421114113"><a name="p17233421114113"></a><a name="p17233421114113"></a>锁类型为TS/TX时，显示等待的DC对应ID；其他锁类型，显示正在获取的ITL。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row84666511303"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p8233112119412"><a name="p8233112119412"></a><a name="p8233112119412"></a>LMODE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p723372184116"><a name="p723372184116"></a><a name="p723372184116"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p923314214416"><a name="p923314214416"></a><a name="p923314214416"></a>锁类型为TS/TX时，显示锁模式：IDLE/S/IX/X；其他锁类型固定为空。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row84666516304"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p142336217414"><a name="p142336217414"></a><a name="p142336217414"></a>BLOCK</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p15233162154117"><a name="p15233162154117"></a><a name="p15233162154117"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1723315217419"><a name="p1723315217419"></a><a name="p1723315217419"></a>锁类型为TS/TX时，显示1 自锁，0被锁；其他锁类型固定为1。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1846716512305"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p18233721174115"><a name="p18233721174115"></a><a name="p18233721174115"></a>RMID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1233112164112"><a name="p1233112164112"></a><a name="p1233112164112"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p82349218417"><a name="p82349218417"></a><a name="p82349218417"></a>锁所在的rmid。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row64677513012"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p8523125712113"><a name="p8523125712113"></a><a name="p8523125712113"></a>cantian.cantian_lock_waits</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p1858071252110"><a name="p1858071252110"></a><a name="p1858071252110"></a>查看锁等待事务信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18467859301"><td class="cellrowborder" rowspan="13" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="13" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p20327518173412"><a name="p20327518173412"></a><a name="p20327518173412"></a>session_id</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1489357171617"><a name="p1489357171617"></a><a name="p1489357171617"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p389175761611"><a name="p389175761611"></a><a name="p389175761611"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row154676563015"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2326518143416"><a name="p2326518143416"></a><a name="p2326518143416"></a>requesting_trx_rmid</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1490483619545"><a name="p1490483619545"></a><a name="p1490483619545"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p159041736165411"><a name="p159041736165411"></a><a name="p159041736165411"></a>TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row127660442319"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p87663442319"><a name="p87663442319"></a><a name="p87663442319"></a>requesting_trx_status</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19031336135411"><a name="p19031336135411"></a><a name="p19031336135411"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6903163615549"><a name="p6903163615549"></a><a name="p6903163615549"></a>TXN的状态。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1085426142315"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p178545672318"><a name="p178545672318"></a><a name="p178545672318"></a>requesting_trx_begin_time</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4904193614547"><a name="p4904193614547"></a><a name="p4904193614547"></a>DATE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1690417362543"><a name="p1690417362543"></a><a name="p1690417362543"></a>TXN被使用时的开始时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2360518133319"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p63601718123316"><a name="p63601718123316"></a><a name="p63601718123316"></a>requesting_trx_exec_time</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p8506091457"><a name="p8506091457"></a><a name="p8506091457"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p135065954518"><a name="p135065954518"></a><a name="p135065954518"></a>TXN执行时长（单位us）</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9154720193314"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1915592013310"><a name="p1915592013310"></a><a name="p1915592013310"></a>blocking_wait_sid</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p11921757111616"><a name="p11921757111616"></a><a name="p11921757111616"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p119205719161"><a name="p119205719161"></a><a name="p119205719161"></a>锁等待的SESSION ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row8973821133314"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p179731421203312"><a name="p179731421203312"></a><a name="p179731421203312"></a>blocking_trx_rmid</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4702174512314"><a name="p4702174512314"></a><a name="p4702174512314"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6702104582310"><a name="p6702104582310"></a><a name="p6702104582310"></a>阻塞的TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1911611245333"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p9116112423320"><a name="p9116112423320"></a><a name="p9116112423320"></a>blocking_trx_status</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p197023452238"><a name="p197023452238"></a><a name="p197023452238"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p870218451235"><a name="p870218451235"></a><a name="p870218451235"></a>阻塞的TXN的状态。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row23821450103314"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1438235019334"><a name="p1438235019334"></a><a name="p1438235019334"></a>blocking_trx_begin_time</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p370234592311"><a name="p370234592311"></a><a name="p370234592311"></a>DATE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p13702045132319"><a name="p13702045132319"></a><a name="p13702045132319"></a>阻塞的TXN被使用时的开始时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9400195214338"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p9401652143312"><a name="p9401652143312"></a><a name="p9401652143312"></a>blocking_trx_exec_time</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p177021545102311"><a name="p177021545102311"></a><a name="p177021545102311"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1470294512235"><a name="p1470294512235"></a><a name="p1470294512235"></a>阻塞的TXN执行时长（单位us）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row518618547335"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1818615417336"><a name="p1818615417336"></a><a name="p1818615417336"></a>lock_type</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p20212921132419"><a name="p20212921132419"></a><a name="p20212921132419"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17212102115247"><a name="p17212102115247"></a><a name="p17212102115247"></a>锁类型：TS/TX/RS/RX/KS/KX。目前使用TS/TX/RX/KX锁，其中TS/TX锁属于表级锁，RX/KX锁属于事务锁。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row14377167345"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p14371616103418"><a name="p14371616103418"></a><a name="p14371616103418"></a>lock_page</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19720143612414"><a name="p19720143612414"></a><a name="p19720143612414"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p672093617241"><a name="p672093617241"></a><a name="p672093617241"></a>锁类型为TS/TX时，显示等待的DC对应用户ID；其他锁类型，显示正在获取的page编号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1671316190341"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p20714111911344"><a name="p20714111911344"></a><a name="p20714111911344"></a>lock_itl</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p17208362247"><a name="p17208362247"></a><a name="p17208362247"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1372083620249"><a name="p1372083620249"></a><a name="p1372083620249"></a>锁类型为TS/TX时，显示等待的DC对应ID；其他锁类型，显示正在获取的ITL。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1563718218342"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p8638152114341"><a name="p8638152114341"></a><a name="p8638152114341"></a>cantian.cantian_locks</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p12638182173416"><a name="p12638182173416"></a><a name="p12638182173416"></a>查看锁等待事务信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13868114019364"><td class="cellrowborder" rowspan="7" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="7" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p19829191083715"><a name="p19829191083715"></a><a name="p19829191083715"></a>session_id</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1838514472616"><a name="p1838514472616"></a><a name="p1838514472616"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p9385345261"><a name="p9385345261"></a><a name="p9385345261"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row37640423366"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p88291210133711"><a name="p88291210133711"></a><a name="p88291210133711"></a>requesting_trx_rmid</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p050101112610"><a name="p050101112610"></a><a name="p050101112610"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6501118262"><a name="p6501118262"></a><a name="p6501118262"></a>TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row57915517369"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p118301510183712"><a name="p118301510183712"></a><a name="p118301510183712"></a>blocking_wait_sid</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p23772186268"><a name="p23772186268"></a><a name="p23772186268"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p193771518112616"><a name="p193771518112616"></a><a name="p193771518112616"></a>锁等待的SESSION ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16253013715"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p36464703814"><a name="p36464703814"></a><a name="p36464703814"></a>blocking_trx_rmid</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p720742562612"><a name="p720742562612"></a><a name="p720742562612"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1320732515264"><a name="p1320732515264"></a><a name="p1320732515264"></a>阻塞的TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row0971155213384"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p109711521383"><a name="p109711521383"></a><a name="p109711521383"></a>lock_type</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p182431530122610"><a name="p182431530122610"></a><a name="p182431530122610"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p4243113032616"><a name="p4243113032616"></a><a name="p4243113032616"></a>锁类型：TS/TX/RS/RX/KS/KX。目前使用TS/TX/RX/KX锁，其中TS/TX锁属于表级锁，RX/KX锁属于事务锁。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row18326175553813"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p132665573815"><a name="p132665573815"></a><a name="p132665573815"></a>lock_page</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p8243193017265"><a name="p8243193017265"></a><a name="p8243193017265"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p182432307263"><a name="p182432307263"></a><a name="p182432307263"></a>锁类型为TS/TX时，显示等待的DC对应用户ID；其他锁类型，显示正在获取的page编号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row116858113815"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p12685833811"><a name="p12685833811"></a><a name="p12685833811"></a>lock_itl</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14243113017264"><a name="p14243113017264"></a><a name="p14243113017264"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1324383052612"><a name="p1324383052612"></a><a name="p1324383052612"></a>锁类型为TS/TX时，显示等待的DC对应ID；其他锁类型，显示正在获取的ITL。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13951631193911"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p0584144715392"><a name="p0584144715392"></a><a name="p0584144715392"></a>cantian.cantian_row_lock_current_waits</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p5951113115392"><a name="p5951113115392"></a><a name="p5951113115392"></a>查看当前正在等待的行锁个数。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1486233493913"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p386303414391"><a name="p386303414391"></a><a name="p386303414391"></a>cantian_row_lock_current_waits</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1664194812176"><a name="p1664194812176"></a><a name="p1664194812176"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p148631434113916"><a name="p148631434113916"></a><a name="p148631434113916"></a>当前正在等待的行锁个数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row167359174216"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p14731999424"><a name="p14731999424"></a><a name="p14731999424"></a>cantian.cantian_row_lock_time_avg</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p6733934219"><a name="p6733934219"></a><a name="p6733934219"></a>查看获得一个行锁的平均时间。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row19981313104211"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p799881364216"><a name="p799881364216"></a><a name="p799881364216"></a>VALUE(us)</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p139981713124211"><a name="p139981713124211"></a><a name="p139981713124211"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p179981713174212"><a name="p179981713174212"></a><a name="p179981713174212"></a>获得一个row lock的平均时间，单位是微秒。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9521318114213"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p15521418124215"><a name="p15521418124215"></a><a name="p15521418124215"></a>cantian.cantian_row_lock_waits</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p13521418104217"><a name="p13521418104217"></a><a name="p13521418104217"></a>查看等待row lock的次数。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row164171634218"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p4412169421"><a name="p4412169421"></a><a name="p4412169421"></a>cantian_row_lock_waits</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p34181604213"><a name="p34181604213"></a><a name="p34181604213"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p1041121624213"><a name="p1041121624213"></a><a name="p1041121624213"></a>cantian表上等待row lock的次数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

# 事务信息<a name="ZH-CN_TOPIC_0000001819458878"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row14960354194611"><th class="cellrowborder" valign="top" width="19.87198719871987%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b214225213612"><a name="b214225213612"></a><a name="b214225213612"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="24.462446244624463%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b914315216362"><a name="b914315216362"></a><a name="b914315216362"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="15.041504150415042%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b2014365283618"><a name="b2014365283618"></a><a name="b2014365283618"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="9.8009800980098%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b714485210364"><a name="b714485210364"></a><a name="b714485210364"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="18.891889188918892%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b71446525363"><a name="b71446525363"></a><a name="b71446525363"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b191441452113614"><a name="b191441452113614"></a><a name="b191441452113614"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row2467164043413"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p87428133134"><a name="p87428133134"></a><a name="p87428133134"></a>cantian.dv_transactions</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p10742151361319"><a name="p10742151361319"></a><a name="p10742151361319"></a>查看事务信息。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row134674405348"><td class="cellrowborder" rowspan="14" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="14" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p8438619171416"><a name="p8438619171416"></a><a name="p8438619171416"></a>SEG_ID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1438619111418"><a name="p1438619111418"></a><a name="p1438619111418"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p44381019131418"><a name="p44381019131418"></a><a name="p44381019131418"></a>TXN（事务区）所在的SEGMENT ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row3466540173419"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p14438319101419"><a name="p14438319101419"></a><a name="p14438319101419"></a>SLOT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p17438191981410"><a name="p17438191981410"></a><a name="p17438191981410"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1643871920146"><a name="p1643871920146"></a><a name="p1643871920146"></a>TXN在TXN PAGE中的SLOT号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1246674053411"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1438161961411"><a name="p1438161961411"></a><a name="p1438161961411"></a>XNUM</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2043881918147"><a name="p2043881918147"></a><a name="p2043881918147"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1443871921413"><a name="p1443871921413"></a><a name="p1443871921413"></a>TXN的版本号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row646620404341"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p144381819131410"><a name="p144381819131410"></a><a name="p144381819131410"></a>SCN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p9438131991415"><a name="p9438131991415"></a><a name="p9438131991415"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p04381419151410"><a name="p04381419151410"></a><a name="p04381419151410"></a>TXN的SCN。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row184661540163417"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p7438719131416"><a name="p7438719131416"></a><a name="p7438719131416"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p743861971419"><a name="p743861971419"></a><a name="p743861971419"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10438519171416"><a name="p10438519171416"></a><a name="p10438519171416"></a>TXN所属的session ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row846694083415"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p12438171910146"><a name="p12438171910146"></a><a name="p12438171910146"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19438131971410"><a name="p19438131971410"></a><a name="p19438131971410"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p64385193141"><a name="p64385193141"></a><a name="p64385193141"></a>TXN的状态。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16466184033416"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1243911916143"><a name="p1243911916143"></a><a name="p1243911916143"></a>UNDO_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1443941911143"><a name="p1443941911143"></a><a name="p1443941911143"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1543931991415"><a name="p1543931991415"></a><a name="p1543931991415"></a>TXN的使用的UNDO PAGE个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1746634023410"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p194397196142"><a name="p194397196142"></a><a name="p194397196142"></a>UNDO_FIRST</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1043915193140"><a name="p1043915193140"></a><a name="p1043915193140"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p74394194141"><a name="p74394194141"></a><a name="p74394194141"></a>TXN使用的第一个UNDO PAGE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row94661940173418"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p9439171921411"><a name="p9439171921411"></a><a name="p9439171921411"></a>UNDO_LAST</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p443981931418"><a name="p443981931418"></a><a name="p443981931418"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17439141912141"><a name="p17439141912141"></a><a name="p17439141912141"></a>TXN使用的最后个UNDO PAGE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row446616408345"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2043911971419"><a name="p2043911971419"></a><a name="p2043911971419"></a>BEGIN_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p74391119121413"><a name="p74391119121413"></a><a name="p74391119121413"></a>DATE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1843961917142"><a name="p1843961917142"></a><a name="p1843961917142"></a>TXN被使用时的开始时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2466204016345"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1843991921410"><a name="p1843991921410"></a><a name="p1843991921410"></a>TXN_PAGEID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p0439619181411"><a name="p0439619181411"></a><a name="p0439619181411"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10439191910145"><a name="p10439191910145"></a><a name="p10439191910145"></a>TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row746634018349"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p144391819181420"><a name="p144391819181420"></a><a name="p144391819181420"></a>RMID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p154398197149"><a name="p154398197149"></a><a name="p154398197149"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p543961920144"><a name="p543961920144"></a><a name="p543961920144"></a>TXN所在的rmid。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row546612409344"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p175193292023"><a name="p175193292023"></a><a name="p175193292023"></a>REMAINED</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p3519152915210"><a name="p3519152915210"></a><a name="p3519152915210"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1551920293220"><a name="p1551920293220"></a><a name="p1551920293220"></a>是否为后台回滚事务，取值“TRUE”或“FALSE”。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16466640123410"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p659963210220"><a name="p659963210220"></a><a name="p659963210220"></a>EXEC_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p7599173210214"><a name="p7599173210214"></a><a name="p7599173210214"></a>BIG INT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1159914321828"><a name="p1159914321828"></a><a name="p1159914321828"></a>事务已执行时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row45251212855"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p41117221984"><a name="p41117221984"></a><a name="p41117221984"></a>cantian.cantian_transactions</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p61117220811"><a name="p61117220811"></a><a name="p61117220811"></a>查看事务信息。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row0363014452"><td class="cellrowborder" rowspan="14" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="14" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p8111132216810"><a name="p8111132216810"></a><a name="p8111132216810"></a>SEG_ID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p111112221482"><a name="p111112221482"></a><a name="p111112221482"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p1311117221086"><a name="p1311117221086"></a><a name="p1311117221086"></a>TXN（事务区）所在的SEGMENT ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row155015168516"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p211117221685"><a name="p211117221685"></a><a name="p211117221685"></a>SLOT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p411116224819"><a name="p411116224819"></a><a name="p411116224819"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1311192214819"><a name="p1311192214819"></a><a name="p1311192214819"></a>TXN在TXN PAGE中的SLOT号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row877814171753"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p191111922587"><a name="p191111922587"></a><a name="p191111922587"></a>XNUM</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p711119221884"><a name="p711119221884"></a><a name="p711119221884"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p911192217819"><a name="p911192217819"></a><a name="p911192217819"></a>TXN的版本号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row138021201853"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p13111522482"><a name="p13111522482"></a><a name="p13111522482"></a>SCN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p411115223815"><a name="p411115223815"></a><a name="p411115223815"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p111117222817"><a name="p111117222817"></a><a name="p111117222817"></a>TXN的SCN。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1537314228516"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p611110221981"><a name="p611110221981"></a><a name="p611110221981"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p181111522988"><a name="p181111522988"></a><a name="p181111522988"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p811212221684"><a name="p811212221684"></a><a name="p811212221684"></a>TXN所属的session ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row109122023754"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2112182212816"><a name="p2112182212816"></a><a name="p2112182212816"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p191122227812"><a name="p191122227812"></a><a name="p191122227812"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1811292213816"><a name="p1811292213816"></a><a name="p1811292213816"></a>TXN的状态。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11967192516517"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p18112172219814"><a name="p18112172219814"></a><a name="p18112172219814"></a>UNDO_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p21127227811"><a name="p21127227811"></a><a name="p21127227811"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p41120221784"><a name="p41120221784"></a><a name="p41120221784"></a>TXN的使用的UNDO PAGE个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row157083271657"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p15112522880"><a name="p15112522880"></a><a name="p15112522880"></a>UNDO_FIRST</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14112222483"><a name="p14112222483"></a><a name="p14112222483"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p51123221887"><a name="p51123221887"></a><a name="p51123221887"></a>TXN使用的第一个UNDO PAGE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row3505129458"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1911216221783"><a name="p1911216221783"></a><a name="p1911216221783"></a>UNDO_LAST</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1411262217812"><a name="p1411262217812"></a><a name="p1411262217812"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p18112122219811"><a name="p18112122219811"></a><a name="p18112122219811"></a>TXN使用的最后个UNDO PAGE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row5690981189"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p4112122213813"><a name="p4112122213813"></a><a name="p4112122213813"></a>BEGIN_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p15112122214817"><a name="p15112122214817"></a><a name="p15112122214817"></a>DATE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p4112102219813"><a name="p4112102219813"></a><a name="p4112102219813"></a>TXN被使用时的开始时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row20141411583"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19112622283"><a name="p19112622283"></a><a name="p19112622283"></a>TXN_PAGEID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p41121221382"><a name="p41121221382"></a><a name="p41121221382"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p311211221088"><a name="p311211221088"></a><a name="p311211221088"></a>TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row25947131387"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1511216220818"><a name="p1511216220818"></a><a name="p1511216220818"></a>RMID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p161129227811"><a name="p161129227811"></a><a name="p161129227811"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1611252218817"><a name="p1611252218817"></a><a name="p1611252218817"></a>TXN所在的rmid。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1051520155816"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p711210229814"><a name="p711210229814"></a><a name="p711210229814"></a>REMAINED</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p111124221487"><a name="p111124221487"></a><a name="p111124221487"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1711215221880"><a name="p1711215221880"></a><a name="p1711215221880"></a>是否为后台回滚事务，取值“TRUE”或“FALSE”。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row8229917488"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p13112112217813"><a name="p13112112217813"></a><a name="p13112112217813"></a>EXEC_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p911212222816"><a name="p911212222816"></a><a name="p911212222816"></a>BIG INT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12112122885"><a name="p12112122885"></a><a name="p12112122885"></a>事务已执行时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row0686124613816"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p156867468814"><a name="p156867468814"></a><a name="p156867468814"></a>cantian.cantian_transactions_cnt_over10s</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p16863464818"><a name="p16863464818"></a><a name="p16863464818"></a>查看超过10s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1190145820811"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p519013583814"><a name="p519013583814"></a><a name="p519013583814"></a>trx_count</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1219016581487"><a name="p1219016581487"></a><a name="p1219016581487"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p219018581083"><a name="p219018581083"></a><a name="p219018581083"></a>超过10s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row290345911813"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p1390319591382"><a name="p1390319591382"></a><a name="p1390319591382"></a>cantian.cantian_transactions_cnt_over60s</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p1903165912816"><a name="p1903165912816"></a><a name="p1903165912816"></a>查看超过60s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row176252011911"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p56254113918"><a name="p56254113918"></a><a name="p56254113918"></a>trx_count</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p17625211090"><a name="p17625211090"></a><a name="p17625211090"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p2625811098"><a name="p2625811098"></a><a name="p2625811098"></a>查看超过60s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1835516318917"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p711618128135"><a name="p711618128135"></a><a name="p711618128135"></a>cantian.cantian_transactions_cnt_over180s</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p1135519318913"><a name="p1135519318913"></a><a name="p1135519318913"></a>查看超过180s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row165201624111318"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p105208246132"><a name="p105208246132"></a><a name="p105208246132"></a>trx_count</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p19520102451315"><a name="p19520102451315"></a><a name="p19520102451315"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p752052401316"><a name="p752052401316"></a><a name="p752052401316"></a>查看超过180s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row94698279134"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p2061515322133"><a name="p2061515322133"></a><a name="p2061515322133"></a>cantian.cantian_transactions_cnt_over600s</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p13469102720134"><a name="p13469102720134"></a><a name="p13469102720134"></a>查看超过600s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row031814414132"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p731854419133"><a name="p731854419133"></a><a name="p731854419133"></a>trx_count</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p173181244181317"><a name="p173181244181317"></a><a name="p173181244181317"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p1123263813341"><a name="p1123263813341"></a><a name="p1123263813341"></a>查看超过600s的事务个数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1071315476137"><td class="cellrowborder" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 "><p id="p87139470139"><a name="p87139470139"></a><a name="p87139470139"></a>cantian.cantian_trx</p>
</td>
<td class="cellrowborder" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 "><p id="p2713184716139"><a name="p2713184716139"></a><a name="p2713184716139"></a>查看当前正在执行的事务信息。</p>
</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row544153017140"><td class="cellrowborder" rowspan="22" valign="top" width="19.87198719871987%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="22" valign="top" width="24.462446244624463%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="15.041504150415042%" headers="mcps1.1.7.1.3 "><p id="p290312368546"><a name="p290312368546"></a><a name="p290312368546"></a>SEG_ID</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p590319366545"><a name="p590319366545"></a><a name="p590319366545"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p2903143612543"><a name="p2903143612543"></a><a name="p2903143612543"></a>TXN（事务区）所在的SEGMENT ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2327153281411"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p190310369545"><a name="p190310369545"></a><a name="p190310369545"></a>SLOT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2903836175418"><a name="p2903836175418"></a><a name="p2903836175418"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p0903193655418"><a name="p0903193655418"></a><a name="p0903193655418"></a>TXN在TXN PAGE中的SLOT号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row834174651519"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1903173618546"><a name="p1903173618546"></a><a name="p1903173618546"></a>XNUM</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2090313615413"><a name="p2090313615413"></a><a name="p2090313615413"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10903936165416"><a name="p10903936165416"></a><a name="p10903936165416"></a>TXN的版本号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row79068477157"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2903536155410"><a name="p2903536155410"></a><a name="p2903536155410"></a>SCN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p590320367546"><a name="p590320367546"></a><a name="p590320367546"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p39031436135416"><a name="p39031436135416"></a><a name="p39031436135416"></a>TXN的SCN。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row186656493156"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1590311361543"><a name="p1590311361543"></a><a name="p1590311361543"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p169031436135416"><a name="p169031436135416"></a><a name="p169031436135416"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1903183685418"><a name="p1903183685418"></a><a name="p1903183685418"></a>TXN所属的session ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row567145151512"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p18903136135410"><a name="p18903136135410"></a><a name="p18903136135410"></a>STATUS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19031336135411"><a name="p19031336135411"></a><a name="p19031336135411"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6903163615549"><a name="p6903163615549"></a><a name="p6903163615549"></a>TXN的状态。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row992115481519"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p199035368548"><a name="p199035368548"></a><a name="p199035368548"></a>UNDO_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p159034369543"><a name="p159034369543"></a><a name="p159034369543"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1290323612545"><a name="p1290323612545"></a><a name="p1290323612545"></a>TXN的使用的UNDO PAGE个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row27931014141613"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p149033365542"><a name="p149033365542"></a><a name="p149033365542"></a>UNDO_FIRST</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p20903936115416"><a name="p20903936115416"></a><a name="p20903936115416"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p4903153635410"><a name="p4903153635410"></a><a name="p4903153635410"></a>TXN使用的第一个UNDO PAGE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1673611163169"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p09031936165414"><a name="p09031936165414"></a><a name="p09031936165414"></a>UNDO_LAST</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1990323617549"><a name="p1990323617549"></a><a name="p1990323617549"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p13903103625414"><a name="p13903103625414"></a><a name="p13903103625414"></a>TXN使用的最后个UNDO PAGE。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row3485111851615"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p199031036125415"><a name="p199031036125415"></a><a name="p199031036125415"></a>BEGIN_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4904193614547"><a name="p4904193614547"></a><a name="p4904193614547"></a>DATE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1690417362543"><a name="p1690417362543"></a><a name="p1690417362543"></a>TXN被使用时的开始时间。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row229622011166"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1290493614544"><a name="p1290493614544"></a><a name="p1290493614544"></a>TXN_PAGEID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1490483619545"><a name="p1490483619545"></a><a name="p1490483619545"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p159041736165411"><a name="p159041736165411"></a><a name="p159041736165411"></a>TXN所在的page ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row295622131614"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p490443611547"><a name="p490443611547"></a><a name="p490443611547"></a>RMID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p5904173665410"><a name="p5904173665410"></a><a name="p5904173665410"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p9904173616549"><a name="p9904173616549"></a><a name="p9904173616549"></a>TXN所在的rmid。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13802182320169"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1690413366546"><a name="p1690413366546"></a><a name="p1690413366546"></a>REMAINED</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19904636165418"><a name="p19904636165418"></a><a name="p19904636165418"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row85237252165"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1190403625410"><a name="p1190403625410"></a><a name="p1190403625410"></a>EXEC_TIME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p19904193695413"><a name="p19904193695413"></a><a name="p19904193695413"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12904936105417"><a name="p12904936105417"></a><a name="p12904936105417"></a>TXN执行时长（单位us）</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row288351711714"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1591155711167"><a name="p1591155711167"></a><a name="p1591155711167"></a>LOCK_WAIT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p39110570166"><a name="p39110570166"></a><a name="p39110570166"></a>VARCHAR(4)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p491205712168"><a name="p491205712168"></a><a name="p491205712168"></a>是否存在锁等待。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row7282352171815"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p323352113415"><a name="p323352113415"></a><a name="p323352113415"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1823312112415"><a name="p1823312112415"></a><a name="p1823312112415"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p18233112112417"><a name="p18233112112417"></a><a name="p18233112112417"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row72125544188"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p123392194118"><a name="p123392194118"></a><a name="p123392194118"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p102331821194115"><a name="p102331821194115"></a><a name="p102331821194115"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12330213414"><a name="p12330213414"></a><a name="p12330213414"></a>锁类型：TS/TX/RS/RX/KS/KX。目前使用TS/TX/RX/KX锁，其中TS/TX锁属于表级锁，RX/KX锁属于事务锁。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row131206562183"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1223352116419"><a name="p1223352116419"></a><a name="p1223352116419"></a>ID1</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p923362118414"><a name="p923362118414"></a><a name="p923362118414"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1423332154117"><a name="p1423332154117"></a><a name="p1423332154117"></a>锁类型为TS/TX时，显示等待的DC对应用户ID；其他锁类型，显示正在获取的page编号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row698715578184"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p8233162144111"><a name="p8233162144111"></a><a name="p8233162144111"></a>ID2</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p523352110415"><a name="p523352110415"></a><a name="p523352110415"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p17233421114113"><a name="p17233421114113"></a><a name="p17233421114113"></a>锁类型为TS/TX时，显示等待的DC对应ID；其他锁类型，显示正在获取的ITL。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row62591204192"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p8233112119412"><a name="p8233112119412"></a><a name="p8233112119412"></a>LMODE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p723372184116"><a name="p723372184116"></a><a name="p723372184116"></a>VARCHAR(20 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p923314214416"><a name="p923314214416"></a><a name="p923314214416"></a>锁类型为TS/TX时，显示锁模式：IDLE/S/IX/X；其他锁类型固定为空。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row67422195"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p142336217414"><a name="p142336217414"></a><a name="p142336217414"></a>BLOCK</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p15233162154117"><a name="p15233162154117"></a><a name="p15233162154117"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1723315217419"><a name="p1723315217419"></a><a name="p1723315217419"></a>锁类型为TS/TX时，显示1 自锁，0被锁；其他锁类型固定为1。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1822534131916"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p18233721174115"><a name="p18233721174115"></a><a name="p18233721174115"></a>RMID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1233112164112"><a name="p1233112164112"></a><a name="p1233112164112"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p82349218417"><a name="p82349218417"></a><a name="p82349218417"></a>锁所在的rmid。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

# io信息<a name="ZH-CN_TOPIC_0000001819618658"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row324132911129"><th class="cellrowborder" valign="top" width="19.931993199319933%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b7326115413613"><a name="b7326115413613"></a><a name="b7326115413613"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="24.602460246024602%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b63271154163613"><a name="b63271154163613"></a><a name="b63271154163613"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="14.84148414841484%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b193288548368"><a name="b193288548368"></a><a name="b193288548368"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="9.8009800980098%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b203281054163614"><a name="b203281054163614"></a><a name="b203281054163614"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="18.891889188918892%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b3329145415366"><a name="b3329145415366"></a><a name="b3329145415366"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b73291854103616"><a name="b73291854103616"></a><a name="b73291854103616"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row547013513308"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 "><p id="p191195717345"><a name="p191195717345"></a><a name="p191195717345"></a>cantian.cantian_data_pending_fsyncs</p>
</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 "><p id="p2091257203410"><a name="p2091257203410"></a><a name="p2091257203410"></a>查询fsync data当前等待数频率。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1347014513301"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p13892057193411"><a name="p13892057193411"></a><a name="p13892057193411"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p989125712341"><a name="p989125712341"></a><a name="p989125712341"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p5881257193419"><a name="p5881257193419"></a><a name="p5881257193419"></a>DBWR disk writes页刷盘次数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1470135203012"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 "><p id="p1899513093013"><a name="p1899513093013"></a><a name="p1899513093013"></a>cantian.cantian_io_stats</p>
</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 "><p id="p288165743418"><a name="p288165743418"></a><a name="p288165743418"></a>查询io信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row104709553012"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p72571437161017"><a name="p72571437161017"></a><a name="p72571437161017"></a>STATISTIC#</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p6257537141015"><a name="p6257537141015"></a><a name="p6257537141015"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p425713372102"><a name="p425713372102"></a><a name="p425713372102"></a>统计项编号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1470158303"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p122571537141016"><a name="p122571537141016"></a><a name="p122571537141016"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p1425783791016"><a name="p1425783791016"></a><a name="p1425783791016"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p4257193711014"><a name="p4257193711014"></a><a name="p4257193711014"></a>统计项名称。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row64709513302"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p12571937141010"><a name="p12571937141010"></a><a name="p12571937141010"></a>CLASS</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p142571237121017"><a name="p142571237121017"></a><a name="p142571237121017"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p2025743717105"><a name="p2025743717105"></a><a name="p2025743717105"></a>统计类型：</p>
<a name="ul15539155017477"></a><a name="ul15539155017477"></a><ul id="ul15539155017477"><li>0：SQL类型</li><li>1：Kernel类型</li><li>2：Instance类型</li></ul>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row63929164326"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p325723751015"><a name="p325723751015"></a><a name="p325723751015"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p925703716103"><a name="p925703716103"></a><a name="p925703716103"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p62571537171015"><a name="p62571537171015"></a><a name="p62571537171015"></a>统计项值。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row102171307353"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 "><p id="p152171101351"><a name="p152171101351"></a><a name="p152171101351"></a>cantian.cantian_log_waits</p>
</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 "><p id="p5217170163512"><a name="p5217170163512"></a><a name="p5217170163512"></a>查询log buffer太小而等待刷新次数频率。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row696321143512"><td class="cellrowborder" valign="top" width="19.931993199319933%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="24.602460246024602%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p9770163518363"><a name="p9770163518363"></a><a name="p9770163518363"></a>cantian_log_waits</p>
</td>
<td class="cellrowborder" valign="top" width="9.8009800980098%" headers="mcps1.1.7.1.4 "><p id="p596317112355"><a name="p596317112355"></a><a name="p596317112355"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" width="18.891889188918892%" headers="mcps1.1.7.1.5 "><p id="p49642019357"><a name="p49642019357"></a><a name="p49642019357"></a>log buffer太小而等待刷新次数频率。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

# buffer pool信息<a name="ZH-CN_TOPIC_0000001866212881"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row649825133020"><th class="cellrowborder" valign="top" width="17.401740174017398%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b138381756133620"><a name="b138381756133620"></a><a name="b138381756133620"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="27.13271327132713%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b1839256103614"><a name="b1839256103614"></a><a name="b1839256103614"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="14.84148414841484%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b38398565363"><a name="b38398565363"></a><a name="b38398565363"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.54115411541154%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b198391456193620"><a name="b198391456193620"></a><a name="b198391456193620"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="17.151715171517154%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b284015643613"><a name="b284015643613"></a><a name="b284015643613"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b1840856143618"><a name="b1840856143618"></a><a name="b1840856143618"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row79891730183419"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p6338194261219"><a name="p6338194261219"></a><a name="p6338194261219"></a>cantian.dv_buffer_pools</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p14469175123013"><a name="p14469175123013"></a><a name="p14469175123013"></a>查询buff pool分配状态。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row29897309346"><td class="cellrowborder" rowspan="6" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="6" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1746914593018"><a name="p1746914593018"></a><a name="p1746914593018"></a>ID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p14469651303"><a name="p14469651303"></a><a name="p14469651303"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p174691593011"><a name="p174691593011"></a><a name="p174691593011"></a>缓存池中集合序号，整个bufferpool默认分成32个集合。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row69881030193414"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2469051304"><a name="p2469051304"></a><a name="p2469051304"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1346935143012"><a name="p1346935143012"></a><a name="p1346935143012"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p346965193020"><a name="p346965193020"></a><a name="p346965193020"></a>缓存集合名称，默认“DATA BUFFER POOL”。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row4988193015349"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p114692533012"><a name="p114692533012"></a><a name="p114692533012"></a>PAGE_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p74691251301"><a name="p74691251301"></a><a name="p74691251301"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p246917516309"><a name="p246917516309"></a><a name="p246917516309"></a>缓存页面大小，默认8192。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row129885307341"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1647014514308"><a name="p1647014514308"></a><a name="p1647014514308"></a>CURRENT_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p164701351304"><a name="p164701351304"></a><a name="p164701351304"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1147075193011"><a name="p1147075193011"></a><a name="p1147075193011"></a>缓存集合中hot page的数量。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row89883306347"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1247013513011"><a name="p1247013513011"></a><a name="p1247013513011"></a>BUFFERS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p174707593014"><a name="p174707593014"></a><a name="p174707593014"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p54701452304"><a name="p54701452304"></a><a name="p54701452304"></a>缓存集合最大可缓存页面数量。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1998893017345"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1447015516303"><a name="p1447015516303"></a><a name="p1447015516303"></a>FREE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p14701055304"><a name="p14701055304"></a><a name="p14701055304"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p84701752303"><a name="p84701752303"></a><a name="p84701752303"></a>缓存集合空闲页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1889065873411"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p44704518308"><a name="p44704518308"></a><a name="p44704518308"></a>cantian.dv_buffer_page_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p154701455307"><a name="p154701455307"></a><a name="p154701455307"></a>查看各类页面的占用情况。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row489018582343"><td class="cellrowborder" rowspan="5" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p14701154306"><a name="p14701154306"></a><a name="p14701154306"></a>POOL_ID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p12470185103010"><a name="p12470185103010"></a><a name="p12470185103010"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p947055103011"><a name="p947055103011"></a><a name="p947055103011"></a>缓存池序号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row9889195810341"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p154701153306"><a name="p154701153306"></a><a name="p154701153306"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p347017512308"><a name="p347017512308"></a><a name="p347017512308"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p174701759307"><a name="p174701759307"></a><a name="p174701759307"></a>页面类型。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row98891058163418"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p747095183015"><a name="p747095183015"></a><a name="p747095183015"></a>CNUM_TOTAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p24704517303"><a name="p24704517303"></a><a name="p24704517303"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p647016514307"><a name="p647016514307"></a><a name="p647016514307"></a>占用的缓存页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row19889135873416"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p12470651305"><a name="p12470651305"></a><a name="p12470651305"></a>CNUM_CLEAN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p84701953308"><a name="p84701953308"></a><a name="p84701953308"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p3470053302"><a name="p3470053302"></a><a name="p3470053302"></a>干净页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row19889195873418"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p94701573019"><a name="p94701573019"></a><a name="p94701573019"></a>CNUM_DIRTY</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1547065153013"><a name="p1547065153013"></a><a name="p1547065153013"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p10470153305"><a name="p10470153305"></a><a name="p10470153305"></a>脏页个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row5837843125219"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p4830643185215"><a name="p4830643185215"></a><a name="p4830643185215"></a>cantian.dv_buffer_page_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p1283084311528"><a name="p1283084311528"></a><a name="p1283084311528"></a>查看各类页面的占用情况。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row6837124355216"><td class="cellrowborder" rowspan="5" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p783014355213"><a name="p783014355213"></a><a name="p783014355213"></a>POOL_ID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p1483044316525"><a name="p1483044316525"></a><a name="p1483044316525"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p783054319520"><a name="p783054319520"></a><a name="p783054319520"></a>缓存序号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1483794385217"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p148314434521"><a name="p148314434521"></a><a name="p148314434521"></a>TYPE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p98312043145219"><a name="p98312043145219"></a><a name="p98312043145219"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p12831104318522"><a name="p12831104318522"></a><a name="p12831104318522"></a>页面类型。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row198371443185214"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p683117435520"><a name="p683117435520"></a><a name="p683117435520"></a>CNUM_TOTAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p178317433522"><a name="p178317433522"></a><a name="p178317433522"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p6831114305213"><a name="p6831114305213"></a><a name="p6831114305213"></a>占用的缓存页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row78377430522"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2083114365216"><a name="p2083114365216"></a><a name="p2083114365216"></a>CNUM_CLEAN</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p283124319527"><a name="p283124319527"></a><a name="p283124319527"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p38313438521"><a name="p38313438521"></a><a name="p38313438521"></a>干净缓存数页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row183754315216"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p8831104375220"><a name="p8831104375220"></a><a name="p8831104375220"></a>CNUM_DIRTY</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1831194319526"><a name="p1831194319526"></a><a name="p1831194319526"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p98311043145220"><a name="p98311043145220"></a><a name="p98311043145220"></a>脏页缓存页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row20491245317"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p598441105318"><a name="p598441105318"></a><a name="p598441105318"></a>cantian.dv_buffer_pools</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p1598481145312"><a name="p1598481145312"></a><a name="p1598481145312"></a>查询buff pool分配状态。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1391213532"><td class="cellrowborder" rowspan="6" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1598451175311"><a name="p1598451175311"></a><a name="p1598451175311"></a>ID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p0984511125310"><a name="p0984511125310"></a><a name="p0984511125310"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p39844119535"><a name="p39844119535"></a><a name="p39844119535"></a>缓存序号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row33312145320"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p12984121165315"><a name="p12984121165315"></a><a name="p12984121165315"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p398401175310"><a name="p398401175310"></a><a name="p398401175310"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p2984191195314"><a name="p2984191195314"></a><a name="p2984191195314"></a>缓存名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row183181255320"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p5984141111531"><a name="p5984141111531"></a><a name="p5984141111531"></a>PAGE_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p149843116534"><a name="p149843116534"></a><a name="p149843116534"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p15984311205319"><a name="p15984311205319"></a><a name="p15984311205319"></a>缓存占页数目。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row0211255317"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p898401111531"><a name="p898401111531"></a><a name="p898401111531"></a>CURRENT_SIZE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12984131105314"><a name="p12984131105314"></a><a name="p12984131105314"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p1198461145312"><a name="p1198461145312"></a><a name="p1198461145312"></a>缓存当前大小。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row10211235318"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p13984811185317"><a name="p13984811185317"></a><a name="p13984811185317"></a>BUFFERS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p209841411205312"><a name="p209841411205312"></a><a name="p209841411205312"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p7984711135318"><a name="p7984711135318"></a><a name="p7984711135318"></a>最大缓存页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row621512195317"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p9984171145311"><a name="p9984171145311"></a><a name="p9984171145311"></a>FREE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p169845113531"><a name="p169845113531"></a><a name="p169845113531"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 "><p id="p13984121145315"><a name="p13984121145315"></a><a name="p13984121145315"></a>空闲页面个数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1059153545610"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p20747142019468"><a name="p20747142019468"></a><a name="p20747142019468"></a>cantian.dv_buffer_recycle_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p347619583015"><a name="p347619583015"></a><a name="p347619583015"></a>查看BUFFER淘汰状态信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1359173535619"><td class="cellrowborder" rowspan="7" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p164769517307"><a name="p164769517307"></a><a name="p164769517307"></a>GaussDB未定义。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1347611513013"><a name="p1347611513013"></a><a name="p1347611513013"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p447685143014"><a name="p447685143014"></a><a name="p447685143014"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row559153510563"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p204762052309"><a name="p204762052309"></a><a name="p204762052309"></a>TOTAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p104762593020"><a name="p104762593020"></a><a name="p104762593020"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row135810358568"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p147619593014"><a name="p147619593014"></a><a name="p147619593014"></a>WAITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p24768518300"><a name="p24768518300"></a><a name="p24768518300"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11581135175610"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1476359306"><a name="p1476359306"></a><a name="p1476359306"></a>AVG_STEP</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p114762533019"><a name="p114762533019"></a><a name="p114762533019"></a>REAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row11582350565"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1947616513018"><a name="p1947616513018"></a><a name="p1947616513018"></a>SPINS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p174761454309"><a name="p174761454309"></a><a name="p174761454309"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row258335165617"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p74767512302"><a name="p74767512302"></a><a name="p74767512302"></a>SLEEPS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p147635193019"><a name="p147635193019"></a><a name="p147635193019"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row858103518562"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p74775510307"><a name="p74775510307"></a><a name="p74775510307"></a>FAILS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p747705153011"><a name="p747705153011"></a><a name="p747705153011"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1694610914579"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p81314155575"><a name="p81314155575"></a><a name="p81314155575"></a>cantian.dv_buffer_access_stats</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p14477155163016"><a name="p14477155163016"></a><a name="p14477155163016"></a>查看BUFFER cache命中率状态信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row16946598579"><td class="cellrowborder" rowspan="4" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p847795113019"><a name="p847795113019"></a><a name="p847795113019"></a>GaussDB未定义。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p1847775173010"><a name="p1847775173010"></a><a name="p1847775173010"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p1747785163012"><a name="p1747785163012"></a><a name="p1747785163012"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row14946179175711"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p0477356309"><a name="p0477356309"></a><a name="p0477356309"></a>TOTAL_ACCESS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p0477955302"><a name="p0477955302"></a><a name="p0477955302"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row194614913575"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p44773517305"><a name="p44773517305"></a><a name="p44773517305"></a>MISS_COUNT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p54771751303"><a name="p54771751303"></a><a name="p54771751303"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1094515965717"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p194778519305"><a name="p194778519305"></a><a name="p194778519305"></a>HIT_RATIO</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p2047718553017"><a name="p2047718553017"></a><a name="p2047718553017"></a>REAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1634579397"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p17638575395"><a name="p17638575395"></a><a name="p17638575395"></a>cantian.cantian_buffer_pool_hit</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p963205710393"><a name="p963205710393"></a><a name="p963205710393"></a>查询buffer pool的命中率。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1883245873912"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p108332058113917"><a name="p108332058113917"></a><a name="p108332058113917"></a>cantian_buffer_pool_hit</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p8833185817395"><a name="p8833185817395"></a><a name="p8833185817395"></a>REAL</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p178331585396"><a name="p178331585396"></a><a name="p178331585396"></a>命中率。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1917741154019"><td class="cellrowborder" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 "><p id="p87281638114215"><a name="p87281638114215"></a><a name="p87281638114215"></a>cantian.cantian_buffer_pool_wait_free</p>
</td>
<td class="cellrowborder" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 "><p id="p017791194013"><a name="p017791194013"></a><a name="p017791194013"></a>查询buffer淘汰状态信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row7877523408"><td class="cellrowborder" rowspan="7" valign="top" width="17.401740174017398%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="7" valign="top" width="27.13271327132713%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.84148414841484%" headers="mcps1.1.7.1.3 "><p id="p15581197118"><a name="p15581197118"></a><a name="p15581197118"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="11.54115411541154%" headers="mcps1.1.7.1.4 "><p id="p5581791511"><a name="p5581791511"></a><a name="p5581791511"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p125819910119"><a name="p125819910119"></a><a name="p125819910119"></a>session Id。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row562711544015"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19586919119"><a name="p19586919119"></a><a name="p19586919119"></a>TOTAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p17581798116"><a name="p17581798116"></a><a name="p17581798116"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p85869817"><a name="p85869817"></a><a name="p85869817"></a>淘汰次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1140115526447"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p25818920117"><a name="p25818920117"></a><a name="p25818920117"></a>WAITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p5582091012"><a name="p5582091012"></a><a name="p5582091012"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p135812914113"><a name="p135812914113"></a><a name="p135812914113"></a>淘汰等待次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row2112135414416"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p158392111"><a name="p158392111"></a><a name="p158392111"></a>AVG_STEP</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2589919111"><a name="p2589919111"></a><a name="p2589919111"></a>REAL</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p65815917120"><a name="p65815917120"></a><a name="p65815917120"></a>平均淘汰步长。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row176932055194418"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p19581790115"><a name="p19581790115"></a><a name="p19581790115"></a>SPINS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1058491813"><a name="p1058491813"></a><a name="p1058491813"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10587919117"><a name="p10587919117"></a><a name="p10587919117"></a>加锁次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13580257204419"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p058491718"><a name="p058491718"></a><a name="p058491718"></a>SLEEPS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p125811917119"><a name="p125811917119"></a><a name="p125811917119"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p35810914114"><a name="p35810914114"></a><a name="p35810914114"></a>睡眠次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1561640124515"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p17581197117"><a name="p17581197117"></a><a name="p17581197117"></a>FAILS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p15585912119"><a name="p15585912119"></a><a name="p15585912119"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p8581591112"><a name="p8581591112"></a><a name="p8581591112"></a>淘汰失败次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

# 信号量<a name="ZH-CN_TOPIC_0000001938259377"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row649825133020"><th class="cellrowborder" valign="top" width="17.4017401740174%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b138381756133620"><a name="b138381756133620"></a><a name="b138381756133620"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="27.132713271327134%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b1839256103614"><a name="b1839256103614"></a><a name="b1839256103614"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="14.891489148914893%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b38398565363"><a name="b38398565363"></a><a name="b38398565363"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.491149114911492%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b198391456193620"><a name="b198391456193620"></a><a name="b198391456193620"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="17.151715171517154%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b284015643613"><a name="b284015643613"></a><a name="b284015643613"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b1840856143618"><a name="b1840856143618"></a><a name="b1840856143618"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row79891730183419"><td class="cellrowborder" valign="top" width="17.4017401740174%" headers="mcps1.1.7.1.1 "><p id="p6338194261219"><a name="p6338194261219"></a><a name="p6338194261219"></a>cantian.cantian_semaphores_session</p>
</td>
<td class="cellrowborder" valign="top" width="27.132713271327134%" headers="mcps1.1.7.1.2 "><p id="p14469175123013"><a name="p14469175123013"></a><a name="p14469175123013"></a>查询会话级信号量等待事件信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.891489148914893%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.491149114911492%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row29897309346"><td class="cellrowborder" rowspan="11" valign="top" width="17.4017401740174%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="11" valign="top" width="27.132713271327134%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.891489148914893%" headers="mcps1.1.7.1.3 "><p id="p125552421262"><a name="p125552421262"></a><a name="p125552421262"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="11.491149114911492%" headers="mcps1.1.7.1.4 "><p id="p14555842122613"><a name="p14555842122613"></a><a name="p14555842122613"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p1255518429267"><a name="p1255518429267"></a><a name="p1255518429267"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row69881030193414"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1355516429268"><a name="p1355516429268"></a><a name="p1355516429268"></a>EVENT#</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p2055544262610"><a name="p2055544262610"></a><a name="p2055544262610"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p165557424265"><a name="p165557424265"></a><a name="p165557424265"></a>事件号。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row4988193015349"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p115558426265"><a name="p115558426265"></a><a name="p115558426265"></a>EVENT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p6555114212267"><a name="p6555114212267"></a><a name="p6555114212267"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1555520429269"><a name="p1555520429269"></a><a name="p1555520429269"></a>事件名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row129885307341"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p455519425265"><a name="p455519425265"></a><a name="p455519425265"></a>P1</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p15551042162614"><a name="p15551042162614"></a><a name="p15551042162614"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p10555242182619"><a name="p10555242182619"></a><a name="p10555242182619"></a>附加参数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row89883306347"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p05555428260"><a name="p05555428260"></a><a name="p05555428260"></a>WAIT_CLASS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p11556184219260"><a name="p11556184219260"></a><a name="p11556184219260"></a>VARCHAR(64 BYTE)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p6556164232616"><a name="p6556164232616"></a><a name="p6556164232616"></a>事件所属类名。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1998893017345"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p755618423269"><a name="p755618423269"></a><a name="p755618423269"></a>TOTAL_WAITS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p9556154212617"><a name="p9556154212617"></a><a name="p9556154212617"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p195561442172616"><a name="p195561442172616"></a><a name="p195561442172616"></a>事件等待次数。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row52235710502"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p18556164211269"><a name="p18556164211269"></a><a name="p18556164211269"></a>TIME_WAITED</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p15567420268"><a name="p15567420268"></a><a name="p15567420268"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p7556164292610"><a name="p7556164292610"></a><a name="p7556164292610"></a>事件已经等待时间（单位：秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row13788189165011"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p35563426261"><a name="p35563426261"></a><a name="p35563426261"></a>TIME_WAITED_MIRCO</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p8556194213267"><a name="p8556194213267"></a><a name="p8556194213267"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p14556442122618"><a name="p14556442122618"></a><a name="p14556442122618"></a>事件已经等待时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row1320141211501"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p13556124217262"><a name="p13556124217262"></a><a name="p13556124217262"></a>AVERAGE_WAIT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1755634214262"><a name="p1755634214262"></a><a name="p1755634214262"></a>BINARY_DOUBLE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p255654222618"><a name="p255654222618"></a><a name="p255654222618"></a>事件已经等待平均时间（单位：秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row854271495018"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p2055619423262"><a name="p2055619423262"></a><a name="p2055619423262"></a>AVERAGE_WAIT_MIRCO</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p3556242102611"><a name="p3556242102611"></a><a name="p3556242102611"></a>BINARY_BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p3556144218262"><a name="p3556144218262"></a><a name="p3556144218262"></a>事件已经等待平均时间（单位：微秒）。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row96801016145018"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1555604282614"><a name="p1555604282614"></a><a name="p1555604282614"></a>TENANT_ID</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p755613421262"><a name="p755613421262"></a><a name="p755613421262"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p12556144282618"><a name="p12556144282618"></a><a name="p12556144282618"></a>租户id。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row946514335509"><td class="cellrowborder" valign="top" width="17.4017401740174%" headers="mcps1.1.7.1.1 "><p id="p446663317504"><a name="p446663317504"></a><a name="p446663317504"></a>cantian.cantian_semaphores_sys</p>
</td>
<td class="cellrowborder" valign="top" width="27.132713271327134%" headers="mcps1.1.7.1.2 "><p id="p646683325016"><a name="p646683325016"></a><a name="p646683325016"></a>查询系统级信号量等待事件信息。</p>
</td>
<td class="cellrowborder" valign="top" width="14.891489148914893%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.491149114911492%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row485318465525"><td class="cellrowborder" rowspan="4" valign="top" width="17.4017401740174%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" rowspan="4" valign="top" width="27.132713271327134%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.891489148914893%" headers="mcps1.1.7.1.3 "><p id="p1466494871719"><a name="p1466494871719"></a><a name="p1466494871719"></a>STATISTIC#</p>
</td>
<td class="cellrowborder" valign="top" width="11.491149114911492%" headers="mcps1.1.7.1.4 "><p id="p18664548151717"><a name="p18664548151717"></a><a name="p18664548151717"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p16664748191717"><a name="p16664748191717"></a><a name="p16664748191717"></a>统计项编号。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row921334955215"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p106641248141713"><a name="p106641248141713"></a><a name="p106641248141713"></a>NAME</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p76649488174"><a name="p76649488174"></a><a name="p76649488174"></a>VARCHAR(64)</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p1966424811717"><a name="p1966424811717"></a><a name="p1966424811717"></a>统计项名称。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row710195195213"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p1966414820174"><a name="p1966414820174"></a><a name="p1966414820174"></a>CLASS</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p1664194812176"><a name="p1664194812176"></a><a name="p1664194812176"></a>INTEGER</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p116642481178"><a name="p116642481178"></a><a name="p116642481178"></a>统计类型：</p>
<a name="ul916655185414"></a><a name="ul916655185414"></a><ul id="ul916655185414"><li>0：SQL类型</li><li>1：Kernel类型</li><li>2：Instance类型</li></ul>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row151335312528"><td class="cellrowborder" valign="top" headers="mcps1.1.7.1.1 "><p id="p766519489172"><a name="p766519489172"></a><a name="p766519489172"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.2 "><p id="p4665164814179"><a name="p4665164814179"></a><a name="p4665164814179"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.3 "><p id="p66653487171"><a name="p66653487171"></a><a name="p66653487171"></a>统计项值。</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

# log信息<a name="ZH-CN_TOPIC_0000001898699752"></a>

<a name="table10793846302"></a>
<table><thead align="left"><tr id="row649825133020"><th class="cellrowborder" valign="top" width="19.2019201920192%" id="mcps1.1.7.1.1"><p id="p74538514306"><a name="p74538514306"></a><a name="p74538514306"></a><strong id="b138381756133620"><a name="b138381756133620"></a><a name="b138381756133620"></a>视图名称</strong></p>
</th>
<th class="cellrowborder" valign="top" width="25.332533253325334%" id="mcps1.1.7.1.2"><p id="p184536523016"><a name="p184536523016"></a><a name="p184536523016"></a><strong id="b1839256103614"><a name="b1839256103614"></a><a name="b1839256103614"></a>视图说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="14.891489148914891%" id="mcps1.1.7.1.3"><p id="p114531057300"><a name="p114531057300"></a><a name="p114531057300"></a><strong id="b38398565363"><a name="b38398565363"></a><a name="b38398565363"></a>字段名</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.49114911491149%" id="mcps1.1.7.1.4"><p id="p1445317533019"><a name="p1445317533019"></a><a name="p1445317533019"></a><strong id="b198391456193620"><a name="b198391456193620"></a><a name="b198391456193620"></a>字段定义</strong></p>
</th>
<th class="cellrowborder" valign="top" width="17.151715171517154%" id="mcps1.1.7.1.5"><p id="p745311513305"><a name="p745311513305"></a><a name="p745311513305"></a><strong id="b284015643613"><a name="b284015643613"></a><a name="b284015643613"></a>字段说明</strong></p>
</th>
<th class="cellrowborder" valign="top" width="11.931193119311931%" id="mcps1.1.7.1.6"><p id="p1745313513302"><a name="p1745313513302"></a><a name="p1745313513302"></a><strong id="b1840856143618"><a name="b1840856143618"></a><a name="b1840856143618"></a>备注</strong></p>
</th>
</tr>
</thead>
<tbody><tr id="row79891730183419"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 "><p id="p6338194261219"><a name="p6338194261219"></a><a name="p6338194261219"></a>cantian.cantian_os_log_pending_fsyncs</p>
</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 "><p id="p14469175123013"><a name="p14469175123013"></a><a name="p14469175123013"></a>查询fsync log当前等待次数。</p>
</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row29897309346"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 "><p id="p125552421262"><a name="p125552421262"></a><a name="p125552421262"></a>VALUE</p>
</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 "><p id="p14555842122613"><a name="p14555842122613"></a><a name="p14555842122613"></a>BIGINT</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p1255518429267"><a name="p1255518429267"></a><a name="p1255518429267"></a>查询fsync log当前等待次数。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row946514335509"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 "><p id="p446663317504"><a name="p446663317504"></a><a name="p446663317504"></a>cantian.cantian_redo_log_pending_writes_session</p>
</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 "><p id="p646683325016"><a name="p646683325016"></a><a name="p646683325016"></a>查询会话级日志写操作被挂起的平均等待时间。</p>
</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row485318465525"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 "><p id="p2853104695217"><a name="p2853104695217"></a><a name="p2853104695217"></a>SID</p>
</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 "><p id="p08771464116"><a name="p08771464116"></a><a name="p08771464116"></a>BINARY_INTEGER</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p885364614522"><a name="p885364614522"></a><a name="p885364614522"></a>会话ID。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row921334955215"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 "><p id="p12213104925219"><a name="p12213104925219"></a><a name="p12213104925219"></a>AVERAGE_WAIT</p>
</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 "><p id="p182132495526"><a name="p182132495526"></a><a name="p182132495526"></a>BINARY_DOUBLE</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p1921317494523"><a name="p1921317494523"></a><a name="p1921317494523"></a>事件已经等待平均时间（单位：秒）。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row710195195213"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 "><p id="p191025175210"><a name="p191025175210"></a><a name="p191025175210"></a>cantian.cantian_redo_log_pending_writes_sys</p>
</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 "><p id="p21017513526"><a name="p21017513526"></a><a name="p21017513526"></a>查询系统级日志写操作被挂起的平均等待时间。</p>
</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
<tr id="row151335312528"><td class="cellrowborder" valign="top" width="19.2019201920192%" headers="mcps1.1.7.1.1 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="25.332533253325334%" headers="mcps1.1.7.1.2 ">&nbsp;&nbsp;</td>
<td class="cellrowborder" valign="top" width="14.891489148914891%" headers="mcps1.1.7.1.3 "><p id="p1713205320523"><a name="p1713205320523"></a><a name="p1713205320523"></a>AVERAGE_WAIT</p>
</td>
<td class="cellrowborder" valign="top" width="11.49114911491149%" headers="mcps1.1.7.1.4 "><p id="p1131753165214"><a name="p1131753165214"></a><a name="p1131753165214"></a>BINARY_DOUBLE</p>
</td>
<td class="cellrowborder" valign="top" width="17.151715171517154%" headers="mcps1.1.7.1.5 "><p id="p18134531529"><a name="p18134531529"></a><a name="p18134531529"></a>事件已经等待平均时间（单位：秒）。</p>
</td>
<td class="cellrowborder" valign="top" width="11.931193119311931%" headers="mcps1.1.7.1.6 ">&nbsp;&nbsp;</td>
</tr>
</tbody>
</table>

