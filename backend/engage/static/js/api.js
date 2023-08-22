
var tournaments_has_next = true;
var tournaments_page = 1;
var state='all'
var game = '0';
var t=0;

// URLs:
var get_tournaments_url = '/api/tournaments/';
var get_list_tournaments = '/api/tournaments/get_tournaments';
var get_html5games_url = '/api/html5_games/';
var get_prizes_url = '/api/tournaments-prizes/';
var get_winners_url = '/api/winners/';
var post_contact_engage_url = "/api/contact/engage/";
var post_contact_support_url = "/api/contact/support/";
var sections_log = '/api/users/sections_log/sections_log/';
//End URLS


var defaultlang="en-us";
var lang = lang_code;
console.log("lang",lang);

function hoo(){
    if(t>=1){
       window.location.hash="#home-tournaments";
      
    }
       }
   


       $("#li_go_premium").on("click", function () {
        setBtnLoading($(this), true);
      
        function upgrade_subsp() {
            return new Promise((resolve, reject) => {
                $.ajax({
                    url: upgrade_subscription.replace("user_uid", user_uid),
                    headers: {
                        "X-CSRFToken": xtoken,
                    },
                    type: "post",
                    data: {},
                    error: function (value) {
                        reject(value);
                    },
                    success: function (value) {
                        value.is_sub
                        resolve(value);
                        if (value.is_sub == 'false')
                        {
                            window.location.href="/secured"
                        }
                        else{
                            window.location.reload(true);
                        }
                    },
                });
            });
        }
      
        upgrade_subsp().then(function (_) {
            //window.location.reload(true);
        }).catch(function (error) {
            showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
        });
      });
    
    

// login phone
function postLogin(data) {

    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/auth/verify_mobile/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                phone_number: data.phone_number,
                csrfmiddlewaretoken: data.csrfmiddlewaretoken
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}

// login otp
function postLoginOTP(data) {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/auth/login/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                code: data.code,
                mobile:data.mobile,
                csrfmiddlewaretoken: data.csrfmiddlewaretoken
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                location.reload();
                resolve(value);
            },
        });
    });
}

// register phone
function postRegister(data) {

    return new Promise((resolve, reject) => {
        $.ajax({
            url: 'api/auth/reg_verify_mobile/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                phone_number: data.phone_number,
                csrfmiddlewaretoken: data.csrfmiddlewaretoken
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}

// register otp
function postRegisterOTP(data) {

    return new Promise((resolve, reject) => {
        $.ajax({
            url: 'api/auth/register/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                code: data.code,
                phone_number:data.phone_number,
                subscription:data.subscription,
                csrfmiddlewaretoken: data.csrfmiddlewaretoken
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}


function postRegister2OTP(data) {

    return new Promise((resolve, reject) => {
        $.ajax({
            url: 'api/auth/register2/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                code: data.code,
                subscription:data.subscription,
                csrfmiddlewaretoken: data.csrfmiddlewaretoken
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}


function postRegister3OTP(data) {

    return new Promise((resolve, reject) => {
        $.ajax({
            url: 'api/auth/register3/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                code: data.code,
                csrfmiddlewaretoken: data.csrfmiddlewaretoken
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}

function getRandom(arr, n) {
    var result = new Array(n),
        len = arr.length,
        taken = new Array(len);
    if (n > len)
        throw new RangeError("getRandom: more elements taken than available");
    while (n--) {
        var x = Math.floor(Math.random() * len);
        result[n] = arr[x in taken ? taken[x] : x];
        taken[x] = --len in taken ? taken[len] : len;
    }
    return result;
}

function tConvert (time) {
    
    var newtime = time.toString().split(' ')[4];
    // Check correct time format and split into components
    newtime = newtime.toString ().match (/^([01]\d|2[0-3])(:)([0-5]\d)(:[0-5]\d)?$/) || [time];
  
    if (newtime.length > 1) { // If time format correct
        newtime = newtime.slice (1);  // Remove full string match value
        newtime[3] = +newtime[0] < 12 ? ' AM' : ' PM'; // Set AM/PM
        newtime[0] = +newtime[0] % 12 || 12; // Adjust hours
    }
    return (parseInt(newtime[0]) < 10 ? '0'+newtime[0] : newtime[0])+newtime[1]+newtime[2]+newtime[3]; // return adjusted time or original string
  }
 
function fillTopUpcomingTournaments(data){
    data.forEach((item,index) => {
       
        var state='upcoming';
        
        locale.setlocale(locale.LC_TIME, 'en_US.UTF-8');
        var start_date = convertDateToUTC(new Date(item.tournament_started));
        var options = { month: 'long'};
        var html = `
            <div class="newsbv-item `+state+`">
                <div class="newsb-thumbnail">
                    <a rel="bookmark"
                    href="/tournaments/${item.slug}">
                        <img src="${item.image}"
                            alt="${item.slug}">
                        <span class="overlay-link"></span>
                    </a>
                </div>

                <div class="newsb-text">
                    <h4 class="newsb-title">
                        <a rel="bookmark"
                        href="/tournaments/${item.slug}">${item.name}</a>
                    </h4>
                    <h3 class="newsb-date">${new Intl.DateTimeFormat('en-US', options).format(start_date)} ${start_date.getDate().toLocaleString(dateLang, options)} <span class="up_on_pre_year">, ${start_date.getFullYear().toLocaleString(dateLang, options)} </span> - <span style='color:#F6236F;'>${tConvert(start_date).toLocaleString(dateLang, options)}  ${item.label_next_time!=null ? item.label_next_time : '' }</span></h3>
                    <div class='middle-text'>
                        <div class='image1'>
                            <i class='fas fa-male'></i>
                            <span>${item.max_participants}</span>
                        </div>
                        <div class='image2'>
                            <i class="fas fa-users"></i>
                            <span>${item.game_name}</span>
                        </div> 
                    </div>
                </div>`;
              
                
                html+=`<p class="post-meta">
                   <i class="fas fa-clock"></i>
                   <i class="fas fa-users"></i>
                   <span>${item.max_participants}</span>
                   </p>`;
                 
                
                html+=`<div class='pool_prize'><span>`+pool_prize+`</span>
                    <i class="fas fa-trophy"></i>
                    ${item.pool_prize !=null ? item.pool_prize : ''}  
                    <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                    </div>`;
                
              
                html+=`<div class='label'>${state}</div>`;
                if(state==ongoing && item.live_link){
                    html+=`<i class='fa fa-eye'></i>
                           <a class='watch_live' onclick=openLiveWindow('${item.live_link}')>WATCH LIVE NOW</a>`;
                }
                //openLiveModal
                
                html+=`<a class='register' href="/tournaments/${item.slug}">REGISTER</a>`;
                
                html+=`</div>`;


                if($('#leaderboards').length!=0 && $('#leaderboards').find('.newsbv-item').length<2){
                    $('#leaderboards').append(html);
                }
           
          
    });
}

function convertDateToUTC(date) { return new Date(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()); }
function load (pg) {
    return new Promise((resolve, reject) => {
        var isMobile = navigator.userAgent.match(/(iPad)|(iPhone)|(iPod)|(android)|(webOS)/i);
        
        var box = $(".tournaments-list");
        var box_mobile = $(".tournaments-list1 .list");
        var content = $(".tournaments-list1");
        content.html("");
        content.addClass("is-loading");
        content.append(
            "<li class='loading-item'><img class='loading-img white' src='/static/img/loading1.gif' /></li>"
        );
        box_mobile.html("");
        box.html("");
        box.addClass("is-loading");
        box.append(
            "<li class='loading-item'><img class='loading-img white' src='/static/img/loading1.gif' /></li>" //me
        );
		tournaments_page = pg;
        $.ajax({
            url: get_list_tournaments,
            headers: {},
            type: "get",
            data: {
                size: (isMobile==true  || $(window).outerWidth() <=768 ? 1000000000 : 6),
                state: state,
                game: game,
                page: tournaments_page,
            },
            error: function (value) {
                setTimeout(function(){get_tournament(game);},2000);
            },
            success: function (data) {
                box.html("");
                box.removeClass("is-loading");
                content.removeClass("is-loading");
                box.find('.loading-item').remove();
                content.find('.loading-item').remove();
               
              

                if(data.data.length == 0){
                    $('.firstTab .back,.firstTab .next').addClass('off');
                    box.html("<span class='no-data'>No Data Found</span>");
                    return;
                }
                paginator({
                    target : document.getElementById("demoB"),
                    total : ($('.all.active').length == 0 ? data.pagination.pages : data.pagination.all_pages),
                    current : pg,
                    click : load,
                    adj : 3
                  });
                now = new Date();
               
                
                if($('.all.active').length == 0){
                    data.data.forEach((item,index) => {
                        var winners="";
                        if(item.top_winners!=null && item.top_winners.length>0){
                            item.top_winners.slice(0, 3).forEach((item,index) => {
                                var html = `
                                    <p>${index+1}. ${item.winner_name}
                                    </p>
                                    `;
                                winners += html;
                            });
                        }
                        var state="";
                        if(new Date(item.end_date) >= now && item.started_on==null)
                        {
                            state='upcoming';
                        }
                        else if(new Date(item.end_date) < now){
                            state='previous';
                        }
                        else {
                            state='ongoing';
                        }
        
                        
                        var start_date = convertDateToUTC(new Date(item.tournament_started));

                        var options = { month: 'long'};
                    
                        var html = `
                            <div class="newsbv-item `+state+`">
                                <div class="newsb-thumbnail">
                                    <a rel="bookmark"
                                    href="/tournaments/${item.slug}">
                                        <img src="${item.image}"
                                            alt="${item.slug}">
                                        <span class="overlay-link"></span>
                                    </a>
                                </div>
        
                                <div class="newsb-text">
                                    <h4 class="newsb-title">
                                        <a rel="bookmark"
                                        href="/tournaments/${item.slug}">${item.name}</a>
                                    </h4>
                                    <h3 class="newsb-date">${new Intl.DateTimeFormat('en-US', options).format(start_date)} ${start_date.getDate()} <span class="up_on_pre_year">, ${start_date.getFullYear()} </span> - <span style='color:#F6236F;'>${tConvert(start_date)} ${item.label_next_time!=null ? item.label_next_time : '' }</span></h3>
                                    <div class='middle-text'>
                                        <div class='image1'>
                                            <i class='fas fa-male'></i>
                                            <span>${item.max_participants}</span>
                                        </div>
                                        <div class='image2'>
                                            <i class="fas fa-users"></i>
                                            <span>${item.game_name}</span>
                                        </div> 
                                    </div>
                                </div>`;
                                if(state=='ongoing'){
                                    if(item.sponsored_by==null){
                                        html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                        <i class="fas fa-trophy"></i>
                                        ${item.pool_prize !=null ? item.pool_prize : ''}  
                                        <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                        </div>`;
                                    }else{
                                        html+=`<div class='sponsored_by'>
                                        <span>Sponsored by</span>
                                        <img src="${item.sponsored_by}" />
                                        </div>`;}
                                    }
                                
                                html+=`<p class="post-meta">
                                <i class="fas fa-clock"></i>
                                <i class="fas fa-users"></i>
                                <span>${item.max_participants}</span>
                                </p>`;
                                if(state=='previous'){
                                    html+=`<div class="winners">
                                            <i class="fas fa-award"></i>
                                            <span>WINNERS </span>
                                            <div>${winners}</div>
                                        </div>`;
                                }   
                                if(state=='upcoming'){
                                    html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                    <i class="fas fa-trophy"></i>
                                    ${item.pool_prize !=null ? item.pool_prize : ''}  
                                    <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                    </div>`;
                                }
                            
                                html+=`<div class='label'>${state}</div>`;
                                if(state=='ongoing' && item.live_link){
                                    html+=`<i class='fa fa-eye'></i>
                                        <a class='watch_live' onclick=openLiveWindow('${item.live_link}')>WATCH LIVE NOW</a>`;
                                }
                                
                                if(state=='upcoming'){
                                    if(item.is_participant){
                                        html+=`<a class='register' href="/tournaments/${item.slug}">VIEW</a>`;
                                    } else {
                                    html+=`<a class='register' href="/tournaments/${item.slug}">REGISTER</a>`;
                                    }
                                }
                                html+=`</div>`;
                        
                    
                            box.append('<div class="package">'+html+'</div>');
                    
        
                        if(state=='upcoming'){
                            $('.mobileversion').find('.package').eq(1).find('.list').append(html);
                        }
                        else if(state=='ongoing'){
                            $('.mobileversion').find('.package').eq(0).find('.list').append(html);
                        }
                        else if(state=='previous'){
                            $('.mobileversion').find('.package').eq(2).find('.list').append(html);
                        }
                        
                        
                        
                    });
                }
                else{
                    data.all_serializer.forEach((item,index) => {
                        var winners="";
                        if(item.top_winners!=null && item.top_winners.length>0){
                            item.top_winners.slice(0, 3).forEach((item,index) => {
                                var html = `
                                    <p>${index+1}. ${item.winner_name}
                                    </p>
                                    `;
                                winners += html;
                            });
                        }
                        var state="";
                        if(new Date(item.end_date) >= now && item.started_on==null)
                        {
                            state='upcoming';
                        }
                        else if(new Date(item.end_date) < now){
                            state='previous';
                        }
                        else {
                            state='ongoing';
                        }
        
                        
                        var start_date = convertDateToUTC(new Date(item.tournament_started));

                        var options = { month: 'long'};
                    
                        var html = `
                            <div class="newsbv-item `+state+`">
                                <div class="newsb-thumbnail">
                                    <a rel="bookmark"
                                    href="/tournaments/${item.slug}">
                                        <img src="${item.image}"
                                            alt="${item.slug}">
                                        <span class="overlay-link"></span>
                                    </a>
                                </div>
        
                                <div class="newsb-text">
                                    <h4 class="newsb-title">
                                        <a rel="bookmark"
                                        href="/tournaments/${item.slug}">${item.name}</a>
                                    </h4>
                                    <h3 class="newsb-date">${new Intl.DateTimeFormat('en-US', options).format(start_date)} ${start_date.getDate()} <span class="up_on_pre_year">, ${start_date.getFullYear()}</span> - <span style='color:#F6236F;'>${tConvert(start_date)} ${item.label_next_time!=null ? item.label_next_time : '' }</span></h3>
                                    <div class='middle-text'>
                                        <div class='image1'>
                                            <i class='fas fa-male'></i>
                                            <span>${item.max_participants}</span>
                                        </div>
                                        <div class='image2'>
                                            <i class="fas fa-users"></i>
                                            <span>${item.game_name}</span>
                                        </div> 
                                    </div>
                                </div>`;
                                if(state=='ongoing'){
                                    if(item.sponsored_by==null){
                                        html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                        <i class="fas fa-trophy"></i>
                                        ${item.pool_prize !=null ? item.pool_prize : ''}  
                                        <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                        </div>`;
                                    }else{
                                        html+=`<div class='sponsored_by'>
                                        <span>Sponsored by</span>
                                        <img src="${item.sponsored_by}" />
                                        </div>`;}
                                    }
                                
                                html+=`<p class="post-meta">
                                <i class="fas fa-clock"></i>
                                <i class="fas fa-users"></i>
                                <span>${item.max_participants}</span>
                                </p>`;
                                if(state=='previous'){
                                    html+=`<div class="winners">
                                            <i class="fas fa-award"></i>
                                            <span>WINNERS </span>
                                            <div>${winners}</div>
                                        </div>`;
                                }   
                                if(state=='upcoming'){
                                    html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                    <i class="fas fa-trophy"></i>
                                    ${item.pool_prize !=null ? item.pool_prize : ''}  
                                    <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                    </div>`;
                                }
                            
                                html+=`<div class='label'>${state}</div>`;
                                if(state=='ongoing' && item.live_link){
                                    html+=`<i class='fa fa-eye'></i>
                                        <a class='watch_live' onclick=openLiveWindow('${item.live_link}')>WATCH LIVE NOW</a>`;
                                }
                                
                                if(state=='upcoming'){
                                    if(item.is_participant){
                                        html+=`<a class='register' href="/tournaments/${item.slug}">VIEW</a>`;
                                    } else {
                                    html+=`<a class='register' href="/tournaments/${item.slug}">REGISTER</a>`;
                                    }
                                }
                                html+=`</div>`;
                        
                    // if(index%2==0){
                            box.append('<div class="package">'+html+'</div>');
                    // }
                    // else
                        // $('.desktopversion .package').eq($('.desktopversion .package').length-1).append(html); 
        
                        if(state=='upcoming'){
                            $('.mobileversion').find('.package').eq(1).find('.list').append(html);
                        }
                        else if(state=='ongoing'){
                            $('.mobileversion').find('.package').eq(0).find('.list').append(html);
                        }
                        else if(state=='previous'){
                            $('.mobileversion').find('.package').eq(2).find('.list').append(html);
                        }
                        
                        
                        
                    });
                }
                
                $('.desktopversion .block_tabs').css('width',(3*$('.desktopversion .package').outerWidth(true)));
                $('.mobileversion').find('.list').each(function(){
                    if($(this).find('.newsbv-item').length!=0){
                        $(this).css('width',($(this).find('.newsbv-item').length*($(this).find('.newsbv-item').width() + 15)));
                        $(this).removeClass('hide')
                     }
                     else{
                        $(this).addClass('hide'); 
                     }
                });
                
                if(tournaments_page==1)
                    $('.firstTab .back').addClass('off');
                else 
                    $('.firstTab .back').removeClass('off');
                if($('.all.active').length == 0){
                    if (data.pagination.pages > tournaments_page) {
                        tournaments_has_next = true;
                        $('.firstTab .next').removeClass('off');
                    } else {
                        tournaments_has_next = false;
                        $('.firstTab .next').addClass('off');
                    }
                }else{
                    if (data.pagination.all_pages > tournaments_page) {
                        tournaments_has_next = true;
                        $('.firstTab .next').removeClass('off');
                    } else {
                        tournaments_has_next = false;
                        $('.firstTab .next').addClass('off');
                    } 
                }
               
                $(window).trigger("resize");
            },
        });
        
    });
  }

function get_tournament(game,str) {
    return new Promise((resolve, reject) => {
        var isMobile = navigator.userAgent.match(/(iPad)|(iPhone)|(iPod)|(android)|(webOS)/i);
        if(tournaments_has_next || str=='prev'){
        var box = $(".tournaments-list");
        var box_mobile = $(".tournaments-list1 .list");
        var content = $(".tournaments-list1");
        content.find(".package .list").html("");

        content.addClass("is-loading");
        content.find('.loading-item').remove();
        content.append(
            "<li class='loading-item'><img class='loading-img white' src='/static/img/loading1.gif' /></li>"
        );
        content.find('.no-data').remove();
        box_mobile.html("");
        box.html("");
        box.addClass("is-loading");
        box.append(
            "<li class='loading-item'><img class='loading-img white' src='/static/img/loading1.gif' /></li>"
        );
        $.ajax({
            url: get_list_tournaments,
            headers: {},
            type: "get",
            data: {
                size: (isMobile==true  || $(window).outerWidth() <=768 ? 1000000000 : 6),
                state: state,
                game: game,
                page: tournaments_page,
            },
            error: function (value) {
                setTimeout(function(){get_tournament(game);},2000);
            },
            success: function (data) {
                box.html("");
                box.removeClass("is-loading");
                content.removeClass("is-loading");
                box.find('.loading-item').remove();
                content.find('.loading-item').remove();
                t=t+1;

                //hashchangeddd();

               
                var new_upcomings = [];
               
                if(data.tournaments.length > 2){
                    new_upcomings = getRandom(data.tournaments, 2);
                }
                else
                    new_upcomings = data.tournaments;
                fillTopUpcomingTournaments(new_upcomings)

                if(data.data.length == 0){
                    $('.firstTab .back,.firstTab .next').addClass('off');
                    box.html("<span class='no-data'>No Data Found</span>");
                    $('.mobileversion').find('.list').addClass('hide'); 
                    return;
                }
                paginator({
                    target : document.getElementById("demoB"),
                    total : ($(window).outerWidth() < 768 || $('.all.active').length == 0 ? data.pagination.pages : data.pagination.all_pages),
                    current : tournaments_page,
                    click : load,
                    adj : 3
                });
                now = new Date();
               
                if($('.all.active').length == 0 || $(window).width() < 768){
                    data.data.forEach((item,index) => {
                        var winners="";
                        if(item.top_winners!=null && item.top_winners.length>0){
                            item.top_winners.slice(0, 3).forEach((item,index) => {
                                var html = `
                                    <p>${index+1}. ${item.winner_name}
                                    </p>
                                    `;
                                winners += html;
                            });
                        }
                        var state="";
                        if(new Date(item.end_date) >= now && item.started_on==null)
                        {
                            state='upcoming';
                        }
                        else if(new Date(item.end_date) < now){
                            state='previous';
                        }
                        else {
                            state='ongoing';
                        }
        
                        
                        var start_date = convertDateToUTC(new Date(item.tournament_started));

                        var options = { month: 'long'};
                    
                        var html = `
                            <div class="newsbv-item  tour_${item.id}  `+state+`">
                                <div class="newsb-thumbnail">
                                    <a rel="bookmark"
                                    href="/tournaments/${item.slug}">
                                        <img src="${item.image}"
                                            alt="${item.slug}">
                                        <span class="overlay-link"></span>
                                    </a>
                                </div>
        
                                <div class="newsb-text">
                                    <h4 class="newsb-title">
                                        <a rel="bookmark"
                                        href="/tournaments/${item.slug}">${item.name}</a>
                                    </h4>
                                    <h3 class="newsb-date">${new Intl.DateTimeFormat('en-US', options).format(start_date)} ${start_date.getDate()} <span class="up_on_pre_year">, ${start_date.getFullYear()} </span> - <span style='color:#F6236F;'>${tConvert(start_date)} ${item.label_next_time!=null ? item.label_next_time : '' }</span></h3>
                                    <div class='middle-text'>
                                        <div class='image1'>
                                            <i class='fas fa-male'></i>
                                            <span>${item.max_participants}</span>
                                        </div>
                                        <div class='image2'>
                                            <i class="fas fa-users"></i>
                                            <span>${item.game_name}</span>
                                        </div> 
                                    </div>
                                </div>`;
                                if(state=='ongoing'){
                                    if(item.sponsored_by==null){
                                        html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                        <i class="fas fa-trophy"></i>
                                        ${item.pool_prize !=null ? item.pool_prize : ''}  
                                        <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                        </div>`;
                                    }else{
                                        html+=`<div class='sponsored_by'>
                                        <span>Sponsored by</span>
                                        <img src="${item.sponsored_by}" />
                                        </div>`;}
                                    }
                                
                                html+=`<p class="post-meta">
                                <i class="fas fa-clock"></i>
                                <i class="fas fa-users"></i>
                                <span>${item.max_participants}</span>
                                </p>`;
                                if(state=='previous'){
                                    html+=`<div class="winners">
                                            <i class="fas fa-award"></i>
                                            <span>WINNERS </span>
                                            <div>${winners}</div>
                                        </div>`;
                                }   
                                if(state=='upcoming'){
                                    html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                    <i class="fas fa-trophy"></i>
                                    ${item.pool_prize !=null ? item.pool_prize : ''}  
                                    <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                    </div>`;
                                }
                            
                                html+=`<div class='label'>${state}</div>`;
                                if(state=='ongoing' && item.live_link){
                                    html+=`<i class='fa fa-eye'></i>
                                        <a class='watch_live' onclick=openLiveWindow('${item.live_link}')>WATCH LIVE NOW</a>`;
                                }
                                
                                if(state=='upcoming'){
                                    if(item.is_participant){
                                        html+=`<a class='register' href="/tournaments/${item.slug}">VIEW</a>`;
                                    } else {
                                    html+=`<a class='register' href="/tournaments/${item.slug}">REGISTER</a>`;
                                    }
                                }
                                html+=`</div>`;
                        
                    // if(index%2==0){
                            box.append('<div class="package">'+html+'</div>');
                    // }
                    // else
                        // $('.desktopversion .package').eq($('.desktopversion .package').length-1).append(html); 
        
                        if(state=='upcoming'){
                            if ($(`.tour_${item.id}`, box_mobile).length === 0) {
                                if($('.mobileversion').find('.package').eq(1).find('.list').length!=0)
                                $('.mobileversion').find('.package').eq(1).find('.list').append(html);
                                else
                                $('.mobileversion').find('.package').eq(1).append('<div class="list">'+ html+'</div>');
                            }
                           
                        }
                        else if(state=='ongoing'){
                            if ($(`.tour_${item.id}`, box_mobile).length === 0) {
                                if($('.mobileversion').find('.package').eq(0).find('.list').length!=0)  
                                $('.mobileversion').find('.package').eq(0).find('.list').append(html);
                                else
                                $('.mobileversion').find('.package').eq(0).append('<div class="list">'+ html+'</div>');

                            }
                            
                        }
                        else if(state=='previous'){
                             if ($(`.tour_${item.id}`, box_mobile).length === 0) 
                             {
                                if($('.mobileversion').find('.package').eq(2).find('.list').length!=0)  
                                $('.mobileversion').find('.package').eq(2).find('.list').append(html);
                                else
                                $('.mobileversion').find('.package').eq(2).append('<div class="list">'+ html+'</div>');
                             }
                           
                        }
                        
                       
                        
                    });
                }
                else{
                    data.all_serializer.forEach((item,index) => {
                        var winners="";
                        if(item.top_winners!=null && item.top_winners.length>0){
                            item.top_winners.slice(0, 3).forEach((item,index) => {
                                var html = `
                                    <p>${index+1}. ${item.winner_name}
                                    </p>
                                    `;
                                winners += html;
                            });
                        }
                        var state="";
                        if(new Date(item.end_date) >= now && item.started_on==null)
                        {
                            state='upcoming';
                        }
                        else if(new Date(item.end_date) < now){
                            state='previous';
                        }
                        else {
                            state='ongoing';
                        }
        
                        
                        var start_date = convertDateToUTC(new Date(item.tournament_started));

                        var options = { month: 'long'};
                    
                        var html = `
                            <div class="newsbv-item `+state+`">
                                <div class="newsb-thumbnail">
                                    <a rel="bookmark"
                                    href="/tournaments/${item.slug}">
                                        <img src="${item.image}"
                                            alt="${item.slug}">
                                        <span class="overlay-link"></span>
                                    </a>
                                </div>
        
                                <div class="newsb-text">
                                    <h4 class="newsb-title">
                                        <a rel="bookmark"
                                        href="/tournaments/${item.slug}">${item.name}</a>
                                    </h4>
                                    <h3 class="newsb-date">${new Intl.DateTimeFormat('en-US', options).format(start_date)} ${start_date.getDate()} <span class="up_on_pre_year">,${start_date.getFullYear()}</span>  - <span style='color:#F6236F;'>${tConvert(start_date)} ${item.label_next_time!=null ? item.label_next_time : '' }</span></h3>
                                    <div class='middle-text'>
                                        <div class='image1'>
                                            <i class='fas fa-male'></i>
                                            <span>${item.max_participants}</span>
                                        </div>
                                        <div class='image2'>
                                            <i class="fas fa-users"></i>
                                            <span>${item.game_name}</span>
                                        </div> 
                                    </div>
                                </div>`;
                                if(state=='ongoing'){
                                    if(item.sponsored_by==null){
                                        html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                        <i class="fas fa-trophy"></i>
                                        ${item.pool_prize !=null ? item.pool_prize : ''}  
                                        <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                        </div>`;
                                    }else{
                                        html+=`<div class='sponsored_by'>
                                        <span>Sponsored by</span>
                                        <img src="${item.sponsored_by}" />
                                        </div>`;}
                                    }
                                
                                html+=`<p class="post-meta">
                                <i class="fas fa-clock"></i>
                                <i class="fas fa-users"></i>
                                <span>${item.max_participants}</span>
                                </p>`;
                                if(state=='previous'){
                                    html+=`<div class="winners">
                                            <i class="fas fa-award"></i>
                                            <span>WINNERS </span>
                                            <div>${winners}</div>
                                        </div>`;
                                }   
                                if(state=='upcoming'){
                                    html+=`<div class='pool_prize'><span>POOL PRIZE</span>
                                    <i class="fas fa-trophy"></i>
                                    ${item.pool_prize !=null ? item.pool_prize : ''}  
                                    <span>${item.pool_prize_amount !=null ? item.pool_prize_amount : '&nbsp;' } </span>
                                    </div>`;
                                }
                            
                                html+=`<div class='label'>${state}</div>`;
                                if(state=='ongoing' && item.live_link){
                                    html+=`<i class='fa fa-eye'></i>
                                        <a class='watch_live' onclick=openLiveWindow('${item.live_link}')>WATCH LIVE NOW</a>`;
                                }
                                
                                if(state=='upcoming'){
                                    if(item.is_participant){
                                        html+=`<a class='register' href="/tournaments/${item.slug}">VIEW</a>`;
                                    } else {
                                    html+=`<a class='register' href="/tournaments/${item.slug}">REGISTER</a>`;
                                    }
                                }
                                html+=`</div>`;
                        
                    
                            box.append('<div class="package">'+html+'</div>');
                    
        
                        if(state=='upcoming'){
                            $('.mobileversion').find('.package').eq(1).find('.list').append(html);
                        }
                        else if(state=='ongoing'){
                            $('.mobileversion').find('.package').eq(0).find('.list').append(html);
                        }
                        else if(state=='previous'){
                            $('.mobileversion').find('.package').eq(2).find('.list').append(html);
                        }
                        
                        
                        
                    });
                }
                
                $('.desktopversion .block_tabs').css('width',(3*$('.desktopversion .package').outerWidth(true)));
                $('.mobileversion').find('.list').each(function(){
                    if($(this).find('.newsbv-item').length!=0){
                        $(this).css('width',($(this).find('.newsbv-item').length*($(this).find('.newsbv-item').width() + 15)));
                        $(this).removeClass('hide')
                     }
                     else{
                        $(this).addClass('hide'); 
                     }
                });
                
                
                if(tournaments_page==1)
                   $('.firstTab .back').addClass('off');
                else 
                    $('.firstTab .back').removeClass('off');
                if($('.all.active').length == 0){
                    if (data.pagination.pages > tournaments_page) {
                        tournaments_has_next = true;
                        $('.firstTab .next').removeClass('off');
                    } else {
                        tournaments_has_next = false;
                        $('.firstTab .next').addClass('off');
                    }
                }else{
                    if (data.pagination.all_pages > tournaments_page) {
                        tournaments_has_next = true;
                        $('.firstTab .next').removeClass('off');
                    } else {
                        tournaments_has_next = false;
                        $('.firstTab .next').addClass('off');
                    } 
                }
                
                
                
                
                $(window).trigger("resize");
            },
        });
        }
    });
}
// get tournaments
function getTournaments(status, btn) {
    state=status;
    tournaments_page=1;
    game = "0";
    if($('#tournaments').find('.drp_select').length!=0){
        game = $('#tournaments').find('.drp_select select').val();
    }
    tournaments_has_next = true;
    
    get_tournament(game,'next');
   
    if (btn) {
        btn = $(btn);
        btn.closest("ul").find("a").removeClass("active");
        btn.addClass("active");
    }

    if(status == 'upcoming')
    {
        $(".newsbv.tournaments-list").find(".package").each(function(){
            var item = $(this).find(".newsbv-item").eq(0);
            if(!$(item).hasClass("upcoming"))
            $(this).remove();
        });       
        
        if($(".newsbv-item.upcoming").length == 0)
        {
            $(".newsbv.tournaments-list").html('<span class="no-data">No Data Found</span>');
            $(".newsbv.tournaments-list1 .package").eq(0).html('<span class="no-data">There are no upcoming tournaments.</span>');
        }
         
    }  
    if(status == 'ongoing')
    {
        $(".newsbv.tournaments-list").find(".package").each(function(){
            var item = $(this).find(".newsbv-item").eq(0);
            if(!$(item).hasClass("ongoing"))
            $(this).remove();
        });
        
        if($(".newsbv-item.ongoing").length == 0)
        {
            $(".newsbv.tournaments-list").html('<span class="no-data">No Data Found</span>');
            $(".newsbv.tournaments-list1 .package").eq(1).html('<span class="no-data">There are no ongoing tournaments.</span>');
            
        }
    }  
    if(status == 'previous')
    {
        $(".newsbv.tournaments-list").find(".package").each(function(){
            var item = $(this).find(".newsbv-item").eq(0);
            if(!$(item).hasClass("previous"))
                $(this).remove();
        });

        if($(".newsbv-item.previous").length == 0)
        {
            $(".newsbv.tournaments-list").html('<span class="no-data">No Data Found</span>');
            $(".newsbv.tournaments-list1 .package").eq(2).html('<span class="no-data">There are no previous tournaments.</span>');
        }   
              
    }  
    
    return false;
}


function goBack(){
    tournaments_page -= 1;
    if(tournaments_page<=0){
        tournaments_page=1;
        return;
    }
    
    var game = "0";
    if($('#tournaments').find('.drp_select').length!=0){
        game = $('#tournaments').find('.drp_select select').val();
    }
    get_tournament(game,'prev');
}
function goNext(){
    var game = "0";
    if($('#tournaments').find('.drp_select').length!=0){
        game = $('#tournaments').find('.drp_select select').val();
    }
    tournaments_page += 1;
    get_tournament(game,'next');
}

function fillTournaments(){
    hiya();
    if($('.firstTab').find('.button-small.active').hasClass('all')){
        getTournaments('all', $('.firstTab').find('.button-small.active'));
    }
    else if($('.firstTab').find('.button-small.active').hasClass('upcoming')){
        getTournaments('upcoming', $('.firstTab').find('.button-small.active'));
    }
    else if($('.firstTab').find('.button-small.active').hasClass('ongoing')){
        getTournaments('ongoing', $('.firstTab').find('.button-small.active'));
    }
    else if($('.firstTab').find('.button-small.active').hasClass('previous')){
        getTournaments('previous', $('.firstTab').find('.button-small.active'));
    }

}

function showVideoAd(){
    if($('#userSub').val() == "free")
       $('#page-content').show(); 
}

var html5games_ajax = null;
// get html5 games
function getHtml5games(type, btn) {
    if (html5games_ajax) html5games_ajax.abort();

    var box = $("#html5games-list");
    box.html("");
    box.append(
        "<li><img class='loading-img' src='/static/img/loading1.gif' /></li>"
    );

    html5games_ajax = $.ajax({
        url: get_html5games_url,
        headers: {},
        type: "get",
        data: {
            game_type: type,
        },
        error: function (value) {
            setTimeout(() => {
                getHtml5games(type);
            }, 2000);
        },
        success: function (value) {
            if(value.length == 0){
                var loading = box.find("li");
                loading.html("<span class='no-data'>No Data Found</span>");
                return;
            }
            box.html("");

            value.results.forEach((item) => {
                // ${is_authenticated ?  'onclick="showVideoAd()"' : ''}
                

                var image = (item.translations[lang]==undefined)?item.translations[defaultlang].image:item.translations[lang].image;

                var html = `
                    <li>
                        <a class="html5-game ${item.is_locked ? 'is-locked' : ''}" 
                           data-target="${is_authenticated ? item.slug : '#login-modal'}" 
                           data-toggle="${is_authenticated ? '' : 'modal'}"
                           >
                            <div class="img">
                                <img src="${image}" alt="${item.game}">
                            </div>
                            <span>${item.game}</span>
                        </a>
                    </li>
                `;

                box.append(html);
            });
        },
    });
    
    if (btn) {
        btn = $(btn);
        btn.closest("ul").find("a").removeClass("active");
        btn.addClass("active");
    }

    return false;
}

var prizes_ajax = null;
// get prizes
function getPrizes(category, prize_type, box, btn) {
    if (prizes_ajax) prizes_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<li style='width: 100%'><img class='loading-img' src='/static/img/loading1.gif' /></li>"
    );

    prizes_ajax = $.ajax({
        url: '/api/tournaments-prizes/',
        headers: {},
        type: "get",
        data: {
            prize_type: prize_type,
            category: category
        },
        error: function (value) {
            setTimeout(() => {
                getPrizes(state);
            }, 2000);
        },
        success: function (value) {
            if(value.length == 0 || value.count==0){
                var loading = box.find("li");
                loading.html("<span class='no-data'>No Data Found</span>");
                return;
            }
            box.html("");
            value.results.forEach((item) => {
                var start_date = item.tournament.start_date.toString();
                var date = start_date.split('T')[0].split('-')[2]+'/'+start_date.split('T')[0].split('-')[1]+'/'+start_date.split('T')[0].split('-')[0];
                
                var html = `
                    <li class="prize-box" data-id="${item.id}">
                        <div class="main-img">
                            <img src="${item.image}" alt="">
                            <a href="/tournaments/${item.tournament.id}">`+join_now+`</a>
                            <i class="fa fa-user" aria-hidden="true"></i>
                            <div class="shape">${item.participants_count}/${item.tournament.max_participants}</div>
                        </div>
                        <div class="content">
                            <span class="name"><p>${item.prize}</p><p style='display:inline-block' class="timer" data-start="${item.tournament.start_date}" data-end="${item.tournament.end_date}">
                            ${date}
                            </p></span>
                            
                        </div>
                    </li>
                `;

                box.append(html);
                //var timer = $(box.find(".prize-box[data-id='" + item.id + "']")[0]).find(".timer");
                //countdownTimeStart(timer);
            });

            $(window).trigger("resize");

        },
    });

    if (btn) {
        btn = $(btn);
        btn.closest("ul").find("a").removeClass("active");
        btn.addClass("active");
    }

    return false;
}

var avatars_ajax;
// get avatars images
function loadAvatars() {
    var box = $(".avatar-drop");
    box.html("");

    avatars_ajax = $.ajax({
        url: get_avatars_url,
        headers: {},
        type: "get",
        error: function (value) {
            setTimeout(() => {
                loadAvatars();
            }, 3000);
        },
        success: function (value) {
            box.html("");

            value.results.forEach((item) => {

                var html = '<img class="avatar-item" src="' + item.image + '" data-id="' + item.id + '">';

                box.append(html);
            });
        },
    });
}

var winners_ajax = null;
// get winners
// function getWinners(game, btn) {
//     if (winners_ajax) winners_ajax.abort();

//     var box = $("#winners-list");
//     box.html("");
//     box.append(
//         `
//             <tr class="loading-tr">
//                 <td><img class='loading-img' src='/loading1.gif' /></td>
//             </tr>
//         `
//     );

//     winners_ajax = $.ajax({
//         url: get_winners_url,
//         headers: {},
//         type: "get",
//         data: {
//             game: game,
//         },
//         error: function (value) {
//             setTimeout(() => {
//                 getWinners(state);
//             }, 2000);
//         },
//         success: function (value) {
//             if(value.length == 0){
//                 var loading = box.find(".loading-tr");
//                 loading.html("<span class='no-data'>No Data Found</span>");
//                 return;
//             }
//             box.html("");
//             var counter = 1;
//             value.forEach((item) => {
//                 var html =
//                     `
//                     <tr>
//                         <td>${item.winner_name}</td>
//                         <td style="width: 0;">${getNumberWithOrdinal(counter)}</td>
//                     </tr>
//                 `;

//                 counter++;

//                 box.append(html);
//             });

//             $(window).trigger("resize");
//         },
//     });

//     if (btn) {
//         btn = $(btn);
//         btn.closest("ul").find("a").removeClass("active");
//         btn.addClass("active");
//     }

//     return false;
// }

//get participants

function getWinners(game, tournament) {
    if($('.home-winners').length!=0){
    if (winners_ajax) winners_ajax.abort();

    var box = $(".sec-3-1 .col-8");
    box.html("");
    box.append(
        `
            <tr class="loading-tr">
                <td><img class='loading-img white' src='/loading1.gif' /></td>
            </tr>
        `
    );

    winners_ajax = $.ajax({
        url: get_winners_url,
        headers: {},
        type: "get",
        data: {
            game: game,
            tournament:tournament
        },
        error: function (value) {
            // setTimeout(() => {
            //     getWinners(state);
            // }, 2000);
        },
        success: function (value) {
            var selected_tournament = $('.drp_tournament .selectize-input').find('.item').attr('data-value');
            var selected_label_tournament = $('.hiddenTournament_select').find('option[value='+selected_tournament+']').attr('label');
            var selected_tournament_date = $('.hiddenTournament_select').find('option[value='+selected_tournament+']').attr('date');
            $('.sec-3-1').find('.date span').text(selected_tournament_date+' '+ (selected_label_tournament!='None' ? selected_label_tournament : ''));
            box.html("");
           
            if(value.length == 0){
                var loading = box.find(".loading-tr");
                loading.html("<span class='no-data'>No Data Found</span>");
                var html =` <h2 class='home-winners-results-title winners-title'>`+$('.hiddenTournament_select').find('option[value='+selected_tournament+']').attr('gname')+` <font color='#F6236F'>&nbsp;&nbsp;&nbsp;  0 `+winner_transl+`</font></h2> <div class='container'><div class='scroll_wrapper'>`;
                box.append(html);
                $('.sec-3-1 .scroll_wrapper,.sec-3-1 .col-8,.sec-3-1 .container').css('height','auto');
                return;
            }
            
            var counter = 1;
            var html =` <h2 class='home-winners-results-title winners-title'>`+$('.hiddenTournament_select').find('option[value='+selected_tournament+']').attr('gname')+" <font color='#F6236F'>&nbsp;&nbsp;&nbsp;  "+ value.length+` `+winner_transl+` </font></h2> <div class='container'><div class='scroll_wrapper'>`;
            value.forEach((item) => {
                if(counter==1 || counter == 5 || counter == 9 || counter == 13){
                    html +=`<div class='package'>`;
                }
                if(counter%4 ==0 ){
                    html +=`<div class='win'><div class='position4'>${getNumberWithOrdinal(counter)} </div><div class='name4'>${item.winner_name}</div></div>`; 

                }
                html +=`<div class='win'><div class='position'>${getNumberWithOrdinal(counter)} </div><div class='name'>${item.winner_name}</div> </div>`;
                if(counter%4 ==0 || counter==value.length){
                    html +=`</div>`;
                }
                counter++;
               
            });
            html+='</div></div>'
            box.append(html);
            $('.sec-3-1').find('.scroll_wrapper').css('width',$('.sec-3-1').find('.package').length*$('.sec-3-1').find('.package').outerWidth(true));
            $(window).trigger("resize");
            if(value.length < 4){
                $('.sec-3-1 .scroll_wrapper,.sec-3-1 .col-8,.sec-3-1 .container').css('height','auto');
            }
           
        },
    });

    return false;
}
}
function get_participants() {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: get_tournament_participants,
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "get",
            data: {
                size: 1000,
                slug: tournament_slug,
                page: participants_page,
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}


function checkLogMenus(){
    $.ajax({
        url: sections_log,
        headers: {
            "X-CSRFToken": xtoken,
        },
        type: "get",
        data: { },
        error: function (value) {
           
        },
        success: function (value) {
            if(value.newTournamentExist==true){
                $('#hometournaments').find('i').show();
            }
            if(value.newGameExist==true){
                $('#homegames').find('i').show();
            }
            if(value.newPriceExist==true){
                $('#a-prize').find('i').show();
            }
            if(value.newWinnerExist==true){
                $('#li_winners').find('i').show();
            }
            if(value.newRedeemExist==true){
                $('#a-redeem').find('i').show();
            }
        },
    });
}







//**********/
/* Navbar Search box */
//**********/
$(function () {
   $('.top-nav .search-box').find('input[name="search"]').keyup(function(){
     if($(this).val().length < 1){
        $('.results-box').hide();
        return;
     }
     $('.results-box').show();
     $('.search-box').submit();
   });
    var search_ajax = null;
    var box = $(".top-nav .search-box .results-box ul");
    $(".top-nav .search-box").submit(function (e) {
        e.preventDefault();

        if (search_ajax) search_ajax.abort();

        var data = getFormData($(this));
        var option = data.data.option;
        var text = data.data.search;
        var url = "";
        box.html("");

        switch (option) {
            case "tournaments":
                url = "/api/tournaments/get_tournaments2/?search="+text;
                break;

            case "games":
                url = "/api/html5_games/?size=6&search=" + text;
                break;

            case "users":
                url = "/api/users/?size=999&search=" + text;
                break;
        }

        var html = `
            <li class="loading-item">
                <img src="/static/img/loading1.gif" class="loading-img white" />
            </li>
            `;

        box.append(html);

        var has_next = true;

        box.off("scroll");
        box.on("scroll", function () {
            var scrollTop = $(this).scrollTop();
            if (scrollTop + $(this).innerHeight() >= this.scrollHeight - 30) {
                if (search_ajax == null) {

                    if (!has_next) return;
    
                    search_ajax = $.ajax({
                        url: url.replace('http:','https:'),
                        headers: {},
                        type: "get",
                        data: {},
                        error: function (data) {
                            search_ajax = null;
                            var html = `
                                    <li class="msg-text">
                                        Check your connection!
                                    </li>
                                    `;
                            box.html(html);
                        },
                        success: function (data) {
                            box.find(".loading-item").remove();
                            search_ajax = null;

                            if (data.next) {
                                has_next = true;
                                url = data.next;
                            } else {
                                has_next = false;
                            }
                            if(option != "tournaments"){
                            if (data.results.length == 0) {
                                var html = `
                                    <li class="msg-text">
                                        No Results Found!
                                    </li>
                                    `;

                                box.append(html);
                            }
                            }
                            else{
                                if (data.data.length == 0) {
                                    var html = `
                                        <li class="msg-text">
                                            No Results Found!
                                        </li>
                                        `;

                                    box.append(html);
                                }
                                data.data.forEach((item) => { 
                                var html = "";
                                    html = `
                                        <li>
                                            <a href="/tournaments/${item.slug}">
                                                <div class="search-left">
                                                    <div class="img">
                                                        <img src="${item.image}" 
                                                        alt="${item.slug}" />
                                                    </div>
                                                </div>
                
                                                <div class="search-right">
                                                    <h2 class="name">${item.name}</h2>
                
                                                    <p class="post-meta">
                                                        <i class="fas fa-clock"></i>
                                                        <span>${
                                                          item.start_date < 0
                                                            ? "Past"
                                                            : "Starts in: " + item.start_date
                                                        }</span>
                                                        <i class="fas fa-users"></i>
                                                        <span>${item.max_participants}</span>
                                                    </p>
                                                </div>
                                            </a>
                                        </li>
                                    `;
                                    box.append(html); 






                                });

                                }

                            data.results.forEach((item) => {
                                log.console(item)

                                if (option == "games") {
                                    log.console("item" + item)
                                    log.console("item+ ${item}")
                                    html = `
                                        <li>
                                            <a class="html5-game ${item.is_locked? 'is-locked': ''}"  data-target="${is_authenticated ? item.slug : '#login-modal'}" 
                                            data-toggle="${is_authenticated ? '' : 'modal'}">
                                                <div class="search-left">
                                                    <div class="img">
                                                        <img src="${item.translations.en-us.image}" alt="${item.slug}" />
                                                    </div>
                                                </div>
                
                                                <div class="search-right">
                                                    <h2 class="name">${item.game}</h2>
                
                                                    <p class="post-meta">
                                                        <span>${item.game_type}</span>
                                                    </p>
                                                </div>
                                            </a>
                
                                        </li>
                                    `;
                                }

                                if (option == "users") {
                                    html = `
                                        <li>
                                            <a href="/profile/${item.uid}">
                                                <div class="search-left">
                                                    <div class="img">
                                                        <img src="${item.avatar}" alt="${item.username}" />
                                                    </div>
                                                </div>
                
                                                <div class="search-right">
                                                    <h2 class="name">${item.username}</h2>
                
                                                    <p class="post-meta">
                                                        <span>${item.country}</span>
                                                    </p>
                                                </div>
                                            </a>
                
                                        </li>
                                    `;
                                }

                                box.append(html);
                            });
                        },
                    });
                }
            }
        });

        box.trigger("scroll");
    });
    checkLogMenus();
    $('.bottom-nav').find('a').each(function(){
        $(this).click(function(){
          if($(this).find('i').css('display')=='block'){
            resetStar(this);
          }
        })
    })
});






//**********/
/* Profile */
//**********/


// set fav friend
function setFriendFavorite(uid) {

    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/users/' + uid + '/set_favorite/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                uid: uid
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}

function removeFriend(uid) {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/users/' + uid + '/remove_friend/',
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                uid: uid
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            },
        });
    });
}

var last_played_games_ajax = null;

function getLastPlayedGames(uid, box, size) {
    if (last_played_games_ajax) last_played_games_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<div style='width: 100%'><img class='loading-img' src='/static/img/loading1.gif' /></div>"
    );


    get_params = {};

    if (size) {
        get_params.size = size;
    }


    last_played_games_ajax = $.ajax({
        url: '/api/users/' + uid + '/last_played_games/',
        headers: {},
        type: "get",
        data: get_params,
        error: function (value) {
            console.log(value);
            // setTimeout(() => {
            //     getLastPlayedGames(uid, box, size);
            // }, 4000);
        },
        success: function (value) {
            if(value.length == 0){
               var loading = box.find("div");
                // loading.html("<span class='no-data'>No Data Found</span>");
                loading.html("");
                var html = `<a class="game no_game" href="/#home-games" style='width:100%;padding-top:4px!important;display:block;'>
                                <div class="img" style='width: 173px;height:115px;'>
                                    <img src="/static/img/start-playing-and-winning.png">
                                </div>
                                <div class='title'>Start playing and Winning!</div>
                                <div class="btn">Click Here and Enjoy</div>
                            </a>`;
                loading.append(html);
                $('.last-played-games-box .link').remove();
                return;
            }
            box.html("");
            value.forEach((item) => {
                var html = `
                    <a class="game html5-game ${item.game.is_locked? 'is-locked': ''}"  data-target="${is_authenticated ? item.game.slug : '#login-modal'}" 
                           data-toggle="${is_authenticated ? '' : 'modal'}">
                        <div class="img">
                            <img src="${item.game.image}"
                                alt="${item.game.game}">
                        </div>
                        <span>${item.game.game}</span>
                    </a>
                `;
                box.append(html);
            });

            $(window).trigger("resize");
        },
    });
    return false;
}

var joined_tournaments_ajax = null;

function getJoinedTournaments(uid, box, size) {
    if (joined_tournaments_ajax) joined_tournaments_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<li style='width: 100%'><img class='loading-img position-static' src='/static/img/loading1.gif' /></li>"
    );

    get_params = {};

    if (size) {
        get_params.size = size;
    }

    joined_tournaments_ajax = $.ajax({
        url: '/api/users/' + uid + '/joined_tournaments/',
        headers: {},
        type: "get",
        data: get_params,
        error: function (value) {
            console.log(value);
            // setTimeout(() => {
            //     getLastPlayedGames(uid, box, size);
            // }, 4000);
        },
        success: function (value) {
            if(value.length == 0){
                var loading = box.find("li");
                // loading.html("<span class='no-data'>No Data Found</span>");
                loading.html("");
                var html = `<a class="game empty" href="/#home-tournaments" style="display:block;text-align:center;">
                                <div class="img" style='max-width: 95px;margin:58px auto 5px;'>
                                    <img src="/static/img/join-tournaments.png" >
                                </div>
                                <div class='title'>Join Tournaments and Win Cash Prizes!</div>
                                <div class="btn">Click Here and Enjoy</div>
                             </a>`;
                loading.append(html);
                
                $('.joined-tournaments-box .link').remove();
                return;
            }
            box.html("");

            value.forEach((item) => {
                var item_date = new Date(item.start_date);
                var html = `
                    <li class="newsbv-item type-2">
                        <div class="newsb-thumbnail">
                            <a href="/tournaments/${item.slug}">
                                <img src="${item.top_image}"
                                    alt="${item.slug}">
                                <span class="overlay-link"></span>
                            </a>
                        </div>

                        <div class="newsb-text">
                            <h4 class="newsb-title">
                                <a href="/tournaments/${item.slug}">${item.name}</a>
                            </h4>

                            <div class="post-meta">
                                <div class="content">
                                    <div>
                                        <img src="/static/img/user.png"
                                            height="18"
                                            alt="">
                                        <span>${item.max_participants}</span>
                                    </div>
                                    <div>
                                        <img src="/static/img/cal.png"
                                            height="18"
                                            alt="">
                                            
                                        <span>${item_date.toLocaleDateString()}<br>${item_date.toLocaleTimeString()}</span>
                                    </div>
                                </div>
                            </div>

                            <div class="text-right">
                                <a href="/tournaments/${item.slug}"
                                class="btn2">`+view+`</a>
                            </div>
                        </div>
                    </li>
                `;

                box.append(html);
               
            });

            $(window).trigger("resize");
        },
    });
    return false;
}

var upcoming_tournaments_ajax = null;

function getUpcomingTournaments(uid, type, box, btn) {
    if (upcoming_tournaments_ajax) upcoming_tournaments_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<li style='width: 100%'><img class='loading-img position-static' src='/static/img/loading1.gif' /></li>"
    );


    get_params = {
        type: type
    };

    upcoming_tournaments_ajax = $.ajax({
        url: '/api/users/' + uid + '/upcoming_tournaments/',
        headers: {},
        type: "get",
        data: get_params,
        error: function (value) {
            console.log(value);
            // setTimeout(() => {
            //     getLastPlayedGames(uid, box, size);
            // }, 4000);
        },
        success: function (value) {
  
            if(value.length == 0){
                var loading = box.find("li");
                //loading.html("<span class='no-data'>No Data Found</span>");
                
                loading.html("");
                var html = `<a class="game empty" href="/#home-tournaments" style="display:block;text-align:center;">
                <div class="img" style="max-width: 95px;margin:58px auto 5px;">
                    <img src="/static/img/join-tournaments.png">
                </div>
                <div class="title">Join Tournaments and Win Cash Prizes!</div>
                <div class="btn">Click Here and Enjoy</div>
             </a>`;
                loading.append(html);
                $('#upcoming-tournaments-list').parents('.expand-box').find('.link').remove();
                return;

            }
            box.html("");
            
            value.forEach((item) => {
                var item_date = new Date(item.start_date);
                var html = `
                    <li class="newsbv-item type-2">
                        <div class="newsb-thumbnail">
                            <a href="/tournaments/${item.slug}">
                                <img src="${item.top_image}"
                                    alt="${item.slug}">
                                <span class="overlay-link"></span>
                            </a>
                        </div>

                        <div class="newsb-text">
                            <h4 class="newsb-title">
                                <a href="/tournaments/${item.slug}">${item.name}</a>
                            </h4>

                            <div class="post-meta">
                                <div class="content">
                                    <div>
                                        <img src="/static/img/user.png"
                                            height="18"
                                            alt="">
                                        <span>${item.max_participants}</span>
                                    </div>
                                    <div>
                                        <img src="/static/img/cal.png"
                                            height="18"
                                            alt="">
                                        <span>${item_date.toLocaleDateString()}<br>${item_date.toLocaleTimeString()}</span>
                                    </div>
                                </div>
                            </div>

                            <div class="text-right">
                                <a href="/tournaments/${item.slug}"
                                class="btn2">`+view+`</a>
                            </div>
                        </div>
                    </li>
                `;

                box.append(html);
            });

            $(window).trigger("resize");
        },
    });

    if (btn) {
        btn = $(btn);
        btn.closest("ul").find("a").removeClass("active");
        btn.addClass("active");
    }

    return false;
}

var played_tournaments_ajax = null;

function getPlayedTournaments(uid, box, btn) {
    if (played_tournaments_ajax) played_tournaments_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<li style='width: 100%'><img class='loading-img position-static' src='/static/img/loading1.gif' /></li>"
    );

    get_params = {};

    played_tournaments_ajax = $.ajax({
        url: '/api/users/' + uid + '/previous_tournaments/',
        headers: {},
        type: "get",
        data: get_params,
        error: function (value) {
            console.log(value);
            // setTimeout(() => {
            //     getLastPlayedGames(uid, box, size);
            // }, 4000);
        },
        success: function (value) {
            if(value.length == 0){
                var loading = box.find("li");
                //loading.html("<span class='no-data'>No Data Found</span>");
                loading.html("");
                var html = `<a class="game empty" href="/#home-tournaments" style="display:block;text-align:center;">
                <div class="img" style="max-width: 95px;margin:58px auto 5px;">
                    <img src="/static/img/join-tournaments.png">
                </div>
                <div class="title">Join Tournaments and Win Cash Prizes!</div>
                <div class="btn">Click Here and Enjoy</div>
             </a>`;
                loading.append(html);
                $('.played-tournaments').parents('.expand-box').find('.link').remove();
                return;
            }

            box.html("");

            value.forEach((item) => {
                var item_date = new Date(item.start_date);
                var html = `
                    <li class="newsbv-item type-2">
                        <div class="newsb-thumbnail">
                            <a href="/tournaments/${item.slug}">
                                <img src="${item.top_image}"
                                    alt="${item.slug}">
                                <span class="overlay-link"></span>
                            </a>
                        </div>

                        <div class="newsb-text">
                            <h4 class="newsb-title">
                                <a href="/tournaments/${item.slug}">${item.name}</a>
                            </h4>

                            <div class="post-meta">
                                <div class="content">
                                    <div>
                                        <img src="/static/img/user.png"
                                            height="18"
                                            alt="">
                                        <span>${item.max_participants}</span>
                                    </div>
                                    <div>
                                        <img src="/static/img/cal.png"
                                            height="18"
                                            alt="">
                                        <span>${item_date.toLocaleDateString()}<br>${item_date.toLocaleTimeString()}</span>
                                    </div>
                                </div>
                            </div>

                            <div class="text-right">
                                <a href="/tournaments/${item.slug}"
                                class="btn2">`+view+`</a>
                            </div>
                        </div>
                    </li>
                `;

                box.append(html);
            });

            $(window).trigger("resize");
        },
    });

    if (btn) {
        btn = $(btn);
        btn.closest("ul").find("a").removeClass("active");
        btn.addClass("active");
    }

    return false;
}

var stickers_ajax = null;

function getStickers(uid, box, size) {
    if (stickers_ajax) stickers_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<div style='width: 100%'><img class='loading-img position-static' src='/static/img/loading1.gif' /></div>"
    );


    get_params = {};

    if (size) {
        get_params.size = size;
    }

    stickers_ajax = $.ajax({
        url: '/api/users/' + uid + '/stickers/',
        headers: {},
        type: "get",
        data: get_params,
        error: function (value) {
            console.log(value);
            // setTimeout(() => {
            //     getLastPlayedGames(uid, box, size);
            // }, 4000);
        },
        success: function (value) {
            if(value.length == 0){
                var loading = box.find("div");
                loading.html("");
               // loading.html("<span class='no-data'>No Data Found</span>");
               var html = `
               <a class="game" href="/#home-tournaments" style="width:100%;display:block;padding-top:7px;">
                   <div class="img" style='max-width: 350px;margin: 44px auto 0px; height: 100px;'>
                       <img src="/static/img/start-collecting-stickers.png" width="100%">
                   </div>
                   <div class='title'>Start collecting stickers by playing any game or tournament</div>
                   <div class="btn">Click Here and Enjoy</div>
               </a>
              `;
              loading.html(html);
              $('.stickers-box .link').remove();
              return;
            }
            box.html("");

            value.forEach((item) => {
                var html = `
                    <a class="stickers" style="cursor: default">
                        <img src="${item.image}"
                            alt="${item.name}">
                    </a>
                `;

                box.append(html);
            });

            $(window).trigger("resize");
        },
    });
    return false;
}

var trophies_ajax = null;

function getTrophies(uid, box, size) {
    if (trophies_ajax) trophies_ajax.abort();

    box = $(box);
    box.html("");
    box.append(
        "<div style='width: 100%'><img class='loading-img position-static' src='/static/img/loading1.gif' /></div>"
    );


    get_params = {};

    if (size) {
        get_params.size = size;
    }


    trophies_ajax = $.ajax({
        url: '/api/users/' + uid + '/trophies/',
        headers: {},
        type: "get",
        data: get_params,
        error: function (value) {
            console.log(value);
            // setTimeout(() => {
            //     getLastPlayedGames(uid, box, size);
            // }, 4000);
        },
        success: function (value) {
            if(value.length == 0){
               var loading = box.find("div");
               // loading.html("<span class='no-data'>No Data Found</span>");
               loading.html("");
               var html = `
               <a class="game" href="/#home-tournaments" style="width:100%;display:block;padding-top:0;">
                   <div class="img" style='max-width: 145px;margin: 48px auto 0;height:104px;position:relative;'>
                       <img src="/static/img/start-collecting-trophies.png" width="100%" style="height:auto;">
                   </div>
                   <div class='title'>Start collecting Trophies and taunt your friends!</div>
                   <div class="btn">Click Here and Enjoy</div>
               </a>
              `;
                box.append(html);
                $('.trophies-box .link').remove();
                return;
            }
            box.html("");

            value.forEach((item) => {
                var html = `
                    <a class="trophies" style="cursor: default">
                        <img src="${item.image}"
                            alt="${item.name}">
                    </a>
                `;

                box.append(html);
            });

            $(window).trigger("resize");
        },
    });
    return false;
}
