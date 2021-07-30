#include <QDebug>
#include <QUrl>
#include <QtCore>
#include <QtNetwork>
#include <QCryptographicHash>
#include <bigint.h>

class Task : public QObject {
    Q_OBJECT
  public:
    Task(QObject *parent = 0, const QString &keyFile = 0,
         const QString &audience = 0, const QString &url = 0)
        : QObject(parent) {
        this->keyFile = keyFile;
        this->audience = audience;
        this->url = url;
    }

  public slots:
    void run() {
        qDebug("Begin...\n");

        QString privateKey;
        QString clientId;
        QString tokenUrl;

        if (!readSettings(keyFile, privateKey, clientId, tokenUrl)) {
            qDebug()
                << "Error reading settings. Check previous errors for details.";
            emit finished();
            return;
        }

        QByteArray message = createToken(clientId, tokenUrl, audience);

        QByteArray token = signToken(message, privateKey);

        QNetworkAccessManager *mgr = new QNetworkAccessManager(this);

        QString idTokan = getIdToken(mgr, token, tokenUrl);

        bool result = callApp(mgr, idTokan, url);
        if (result) {
            qWarning() << "Success. Your call was authenticated by IAP";
        } else {
            qWarning() << "Error Check debug messages for details";
        }

        delete (mgr);
        emit finished();
    }

  signals:
    void finished();

  private:
    QString audience;
    QString keyFile;
    QString url;
    const QByteArray PADDING = QByteArray::fromHex(
        "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ff"
        "ffffffffffffffffffffffffffffffffffffffffffffffff00");
    const QByteArray ANS1_SHA256_MAGIC =
        QByteArray::fromHex("3031300d060960864801650304020105000420");

    bool callApp(QNetworkAccessManager *mgr, const QString &token,
                 const QString &siteUrl) {
        const QUrl url(siteUrl);
        QNetworkRequest request(url);
        request.setRawHeader("Authorization", ("Bearer " + token).toUtf8());
        QNetworkReply *reply = mgr->get(request);

        QTimer timer;
        timer.setSingleShot(true);

        QEventLoop loop;
        connect(&timer, SIGNAL(timeout()), &loop, SLOT(quit()));
        connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
        timer.start(30000); // 30 secs. timeout
        loop.exec();

        if (timer.isActive()) {
            timer.stop();
            if (reply->error() > 0) {
                qDebug() << reply->errorString();
                // This is valid only for http requests
                qDebug() << "Status:"
                         << reply
                                ->attribute(
                                    QNetworkRequest::HttpStatusCodeAttribute)
                                .toInt();
                qDebug() << "Message:" << reply->readAll();
            } else {
                int statusCode =
                    reply->attribute(QNetworkRequest::HttpStatusCodeAttribute)
                        .toInt();

                if (statusCode != 200) { // Success
                    qDebug() << "Status:" << statusCode;
                    qDebug() << "Message:" << reply->readAll();
                } else {
                    qDebug() << "Status:" << statusCode;
                    return true;
                }
            }
        } else {
            // timeout
            disconnect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
            reply->abort();
        }
        reply->deleteLater();
        return false;
    }

    bool readSettings(const QString &fileNamae, QString &privateKey,
                      QString &clientId, QString &tokenUrl) {
        QString val;
        QFile file;
        file.setFileName(fileNamae);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qDebug() << "Error open file " << fileNamae << ": "
                     << file.errorString();
            return false;
        }

        val = file.readAll();
        file.close();

        // TODO: handle errors
        QJsonDocument d = QJsonDocument::fromJson(val.toUtf8());
        QJsonObject obj = d.object();
        privateKey = obj.value(QString("private_key")).toString();
        clientId = obj.value(QString("client_email")).toString();
        tokenUrl = obj.value(QString("token_uri")).toString();
        return true;
    }

    QByteArray createToken(const QString &clientId, const QString &tokenUrl,
                           const QString audience) {
        QString header = QString("{\"typ\":\"JWT\",\"alg\":\"RS256\"}");
        QString headerBase64 = header.toUtf8().toBase64();

        uint unixTime = QDateTime::currentDateTime().toSecsSinceEpoch();

        QString payload =
            QString("{\"iss\":\"%1\",\"aud\":\"%2\",\"exp\":\"%3\","
                    "\"iat\":\"%4\",\"target_audience\":\"%5\"}")
                .arg(clientId, tokenUrl)
                .arg(unixTime + 3600)
                .arg(unixTime)
                .arg(audience);

        QString payloadBase64 = payload.toUtf8().toBase64();
        return (headerBase64 + "." + payloadBase64).toUtf8();
    }

    QString getIdToken(QNetworkAccessManager *mgr, const QByteArray &token,
                       const QString &fromUrl) {
        const QUrl url(fromUrl);
        QNetworkRequest request(url);
        request.setHeader(QNetworkRequest::ContentTypeHeader,
                          "application/json");

        QByteArray data =
            QString("{\"grant_type\":\"urn:ietf:params:oauth:grant-"
                    "type:jwt-bearer\",\"assertion\":\"%1\"}")
                .arg(token)
                .toUtf8();

        QNetworkReply *reply = mgr->post(request, data);

        QTimer timer;
        timer.setSingleShot(true);

        QEventLoop loop;
        connect(&timer, SIGNAL(timeout()), &loop, SLOT(quit()));
        connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
        timer.start(30000); // 30 secs. timeout
        loop.exec();

        if (timer.isActive()) {
            timer.stop();
            if (reply->error() > 0) {
                qDebug() << reply->errorString();
                // This is valid only for http requests
                qDebug() << "Status:"
                         << reply
                                ->attribute(
                                    QNetworkRequest::HttpStatusCodeAttribute)
                                .toInt();
                qDebug() << "Message:" << reply->readAll();
            } else {
                int statusCode =
                    reply->attribute(QNetworkRequest::HttpStatusCodeAttribute)
                        .toInt();

                if (statusCode != 200) { // Success
                    qDebug() << "Status:" << statusCode;
                    qDebug() << "Message:" << reply->readAll();
                } else {
                    QJsonDocument token =
                        QJsonDocument::fromJson(reply->readAll());
                    QJsonObject tokenData = token.object();
                    reply->deleteLater();
                    return tokenData["id_token"].toString();
                }
            }
        } else {
            // timeout
            disconnect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
            reply->abort();
        }
        reply->deleteLater();
        return NULL;
    }

    QByteArray signToken(const QByteArray &message, const QString &privKey) {
        QString privateKey(privKey);
        privateKey.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKey.replace("\n-----END PRIVATE KEY-----\n", "");
        privateKey.replace("\n", "");

        QByteArray priv = QByteArray::fromBase64(privateKey.toUtf8());

        QByteArray hash = QCryptographicHash::hash(
            message, QCryptographicHash::Algorithm::Sha256);

        hash = PADDING + ANS1_SHA256_MAGIC + hash;

        BigInt n = fromArray(priv.mid(37, 257));
        BigInt e = fromArray(priv.mid(303, 256));
        BigInt m = fromArray(hash);

        QByteArray sign = toArray(BigInt::powm(m, e, n));

        QByteArray token = message + "." + sign.toBase64();

        return token;
    }

    BigInt fromArray(const QByteArray &array) const {
        BigInt res = 0;
        res.fromHex(array.toHex().toStdString());
        return res;
    }

    QByteArray toArray(const BigInt &i) const {
        QByteArray res;
        res = QByteArray::fromHex(QByteArray::fromStdString(i.getString(16)));
        return res;
    }
};

#include "main.moc"

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    Task *task = new Task(&a, argv[1], argv[2], argv[3]);

    QObject::connect(task, SIGNAL(finished()), &a, SLOT(quit()));

    QTimer::singleShot(0, task, SLOT(run()));

    return a.exec();
}
