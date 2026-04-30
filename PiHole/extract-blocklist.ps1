# Curated ad/tracker blocklist from all major adblock testers
# Sources: d3ward toolz, adblock-tester.com, canyoublockit.com, GSecurity Ad Shield
$outFile = Join-Path $PSScriptRoot "blocklist.txt"

$domains = @(
    # ══════════════════════════════════════════════
    # d3ward adblock test (133 domains)
    # ══════════════════════════════════════════════

    # Google Ads
    "pagead2.googlesyndication.com","pagead2.googleadservices.com",
    "ads.google.com","adservice.google.com","afs.googlesyndication.com",
    "adservice.google.co.in",

    # Doubleclick
    "doubleclick.net","ad.doubleclick.net","static.doubleclick.net",
    "m.doubleclick.net","mediavisor.doubleclick.net","stats.g.doubleclick.net",
    "googleads.g.doubleclick.net","pubads.g.doubleclick.net",

    # AdColony
    "adcolony.com","ads30.adcolony.com","adc3-launch.adcolony.com",
    "events3alt.adcolony.com","wd.adcolony.com",

    # Media.net
    "media.net","static.media.net","adservetx.media.net",

    # Google Analytics
    "google-analytics.com","ssl.google-analytics.com","click.googleanalytics.com",

    # Hotjar
    "hotjar.com","api-hotjar.com","hotjar-analytics.com","static.hotjar.com",
    "adm.hotjar.com","identify.hotjar.com","insights.hotjar.com",
    "script.hotjar.com","surveys.hotjar.com","careers.hotjar.com","events.hotjar.io",

    # MouseFlow
    "mouseflow.com","a.mouseflow.com","cdn.mouseflow.com","o2.mouseflow.com",
    "gtm.mouseflow.com","api.mouseflow.com","tools.mouseflow.com","cdn-test.mouseflow.com",

    # FreshMarketer
    "freshmarketer.com","claritybt.freshmarketer.com","fwtracks.freshmarketer.com",

    # LuckyOrange
    "luckyorange.com","luckyorange.net","api.luckyorange.com","realtime.luckyorange.com",
    "cdn.luckyorange.com","w1.luckyorange.com",
    "upload.luckyorange.net","cs.luckyorange.net","settings.luckyorange.net",

    # Stats WP
    "stats.wp.com",

    # Bugsnag
    "notify.bugsnag.com","sessions.bugsnag.com","api.bugsnag.com","app.bugsnag.com",

    # Sentry
    "browser.sentry-cdn.com","app.getsentry.com",

    # Facebook
    "pixel.facebook.com","analytics.facebook.com","ads.facebook.com",
    "an.facebook.com","connect.facebook.net",

    # Twitter
    "ads-twitter.com","static.ads-twitter.com","ads-api.twitter.com",
    "advertising.twitter.com","analytics.twitter.com",

    # LinkedIn
    "ads.linkedin.com","analytics.pointdrive.linkedin.com",

    # Pinterest
    "ads.pinterest.com","log.pinterest.com","ads-dev.pinterest.com",
    "analytics.pinterest.com","trk.pinterest.com","trk2.pinterest.com","widgets.pinterest.com",

    # Reddit
    "ads.reddit.com","pixel.reddit.com","events.reddit.com",
    "events.redditmedia.com","rereddit.com","d.reddit.com",

    # YouTube
    "ads.youtube.com","youtubeads.googleapis.com","analytics.youtube.com",
    "video-stats.video.google.com","youtube.cleverads.vn",

    # TikTok
    "analytics.tiktok.com","ads.tiktok.com","ads-sg.tiktok.com",
    "analytics-sg.tiktok.com","ads-api.tiktok.com","business-api.tiktok.com",
    "log.byteoversea.com",

    # Yahoo
    "ads.yahoo.com","adserver.yahoo.com","global.adserver.yahoo.com",
    "adspecs.yahoo.com","advertising.yahoo.com","analytics.yahoo.com",
    "analytics.query.yahoo.com","comet.yahoo.com","log.fc.yahoo.com",
    "ganon.yahoo.com","gemini.yahoo.com","beap.gemini.yahoo.com",
    "geo.yahoo.com","marketingsolutions.yahoo.com","pclick.yahoo.com",
    "ads.yap.yahoo.com","m.yap.yahoo.com","partnerads.ysm.yahoo.com",
    "udcm.yahoo.com","adtech.yahooinc.com",

    # Yandex
    "appmetrica.yandex.com","appmetrica.yandex.ru","yandexadexchange.net",
    "adfox.yandex.ru","adsdk.yandex.ru","an.yandex.ru","awaps.yandex.ru",
    "awsync.yandex.ru","bs.yandex.ru","bs-meta.yandex.ru","clck.yandex.ru",
    "informer.yandex.ru","kiks.yandex.ru","mc.yandex.ru","metrika.yandex.ru",
    "share.yandex.ru","offerwall.yandex.net","extmaps-api.yandex.net",
    "adfstat.yandex.ru",

    # Unity
    "unityads.unity3d.com","auction.unityads.unity3d.com",
    "config.unityads.unity3d.com","adserver.unityads.unity3d.com",
    "webview.unityads.unity3d.com",

    # Realme
    "bdapi-in-ads.realmemobile.com","bdapi-ads.realmemobile.com",
    "iot-eu-logser.realme.com","iot-logser.realme.com",

    # Xiaomi
    "api.ad.xiaomi.com","data.mistat.xiaomi.com","data.mistat.intl.xiaomi.com",
    "data.mistat.india.xiaomi.com","data.mistat.rus.xiaomi.com",
    "sdkconfig.ad.xiaomi.com","sdkconfig.ad.intl.xiaomi.com",
    "globalapi.ad.xiaomi.com","tracking.miui.com","tracking.intl.miui.com",
    "tracking.rus.miui.com",

    # OPPO
    "adsfs.oppomobile.com","adx.ads.oppomobile.com",
    "ck.ads.oppomobile.com","data.ads.oppomobile.com",

    # Huawei
    "metrics.data.hicloud.com","metrics2.data.hicloud.com",
    "logservice.hicloud.com","logservice1.hicloud.com",
    "logbak.hicloud.com","grs.hicloud.com",

    # OnePlus
    "analytics.oneplus.cn","click.oneplus.cn","click.oneplus.com","open.oneplus.net",

    # Samsung
    "samsungadhub.com","samsungads.com","smetrics.samsung.com","nmetrics.samsung.com",
    "analytics.samsungknox.com","bigdata.ssp.samsung.com","config.samsungads.com",
    "samsung-com.112.2o7.net","analytics-api.samsunghealthcn.com",

    # Apple
    "metrics.apple.com","securemetrics.apple.com","supportmetrics.apple.com",
    "metrics.icloud.com","metrics.mzstatic.com","iadsdk.apple.com",
    "books-analytics-events.apple.com","stocks-analytics-events.apple.com",
    "weather-analytics-events.apple.com","notes-analytics-events.apple.com",
    "api-adservices.apple.com",

    # Amazon
    "amazon-adsystem.com","advertising-api-eu.amazon.com",
    "amazonaax.com","amazonclix.com","assoc-amazon.com",
    "adtago.s3.amazonaws.com","analyticsengine.s3.amazonaws.com",
    "analytics.s3.amazonaws.com","advice-ads.s3.amazonaws.com",

    # FastClick
    "fastclick.com","fastclick.net","media.fastclick.net","cdn.fastclick.net",

    # ══════════════════════════════════════════════
    # adblock-tester.com services
    # ══════════════════════════════════════════════
    "googlesyndication.com","googleadservices.com","googletagmanager.com",
    "googletagservices.com","partner.googleadservices.com",

    # ══════════════════════════════════════════════
    # GSecurity Ad Shield + PAC file domains
    # ══════════════════════════════════════════════
    "adnxs.com","taboola.com","outbrain.com","criteo.com","scorecardresearch.com",
    "pubmatic.com","rubiconproject.com","quantserve.com","quantcast.com",
    "omniture.com","comscore.com","krux.com","bluekai.com","exelate.com",
    "adform.com","adroll.com","vungle.com","inmobi.com","flurry.com",
    "mixpanel.com","heap.io","amplitude.com","optimizely.com","bizible.com",
    "pardot.com","hubspot.com","marketo.com","eloqua.com","appnexus.com",
    "adbrite.com","admob.com","adsonar.com","zergnet.com","revcontent.com",
    "mgid.com","adblade.com","chartbeat.com","newrelic.com","pingdom.net",
    "kissmetrics.com","tradedesk.com","turn.com","adscale.com","bannerflow.com",
    "nativeads.com","contentad.com","displayads.com","adsafeprotected.com",
    "moatads.com","adtech.de","adform.net","serving-sys.com",
    "smartadserver.com","openx.net","casalemedia.com","indexww.com",
    "sharethrough.com","33across.com","triplelift.com","sovrn.com","lijit.com",
    "bidswitch.net","yieldmo.com","teads.tv","spotxchange.com","springserve.com",
    "contextweb.com","liveintent.com",

    # Segment / Session recording
    "segment.io","segment.com","fullstory.com",

    # ══════════════════════════════════════════════
    # Adult site ad networks
    # ══════════════════════════════════════════════
    "trafficjunky.com","trafficjunky.net","trafficstars.com","tsyndicate.com",
    "exoclick.com","exosrv.com","exoticads.com","juicyads.com","realsrv.com",
    "magsrv.com","syndication.exoclick.com","main.exoclick.com",
    "static.exoclick.com","ads.trafficjunky.net","cdn.trafficjunky.net",
    "a.realsrv.com","syndication.realsrv.com","s.magsrv.com",
    "padsdel.com","adsrv.org",

    # ══════════════════════════════════════════════
    # Additional common ad/tracking domains
    # ══════════════════════════════════════════════
    "byteoversea.com","yahooinc.com",
    "2mdn.net","2o7.net","adnxs.net","adsrvr.org","demdex.net",
    "doubleverify.com","eyeota.net","mathtag.com","mookie1.com",
    "nexac.com","rfihub.com","rlcdn.com","rubiconproject.net",
    "sascdn.com","simpli.fi","sitescout.com","tidaltv.com",
    "tynt.com","undertone.com","w55c.net","weborama.com",
    "zemanta.com","zqtk.net","brightcove.com/tracking",
    "crazyegg.com","inspectlet.com","loggly.com",
    "nr-data.net","onesignal.com","pushwoosh.com",
    "tapad.com","tealiumiq.com","treasuredata.com",
    "visualwebsiteoptimizer.com","webtrends.com"
)

$domains = $domains | Sort-Object -Unique
$domains | Out-File $outFile -Encoding UTF8
Write-Host "Created blocklist.txt with $($domains.Count) curated domains from all major adblock testers" -ForegroundColor Green
