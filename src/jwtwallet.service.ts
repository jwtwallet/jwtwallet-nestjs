import { Inject, Injectable, Logger } from "@nestjs/common";
import { ConfigModuleBuilder } from "./jwtwallet.module-definition";
import { JWTWalletModuleModuleOptions } from "./jwtwallet.module-options.interface";

import type { webcrypto } from "crypto";
import * as jose from "jose";
import { FlattenedJWSInput, JWSHeaderParameters } from "jose";
import { v4 } from "uuid";
import {
  KeyIdDidNotMatchError,
  KeyMissingError,
  PrivateKeyMissingError,
  SaveTokenExitError,
  UndefinedAlgoritmError
} from "./jwtwallet.errors";

const DEFAULT_ALGORITHM_FOR_DEVELOPMENT = "ES256";

@Injectable()
export class JWTWalletService {
  private logger = new Logger(JWTWalletService.name);
  private keyFunction: jose.GetKeyFunction<
    JWSHeaderParameters,
    FlattenedJWSInput
  >;

  private privateKey?: webcrypto.CryptoKey;
  private privateKeyAlgoritm?: string;
  private privateKeyKid?: string;
  private publicKey?: webcrypto.CryptoKey;

  private issuer?: string;

  constructor(
    @Inject(ConfigModuleBuilder.MODULE_OPTIONS_TOKEN)
    private options: JWTWalletModuleModuleOptions
  ) {
    void this.publicKeyInit(options);
    void this.privateKeyInit(options);
  }

  private async generateKeys() {
    const algorithm = DEFAULT_ALGORITHM_FOR_DEVELOPMENT;
    const keys = await jose.generateKeyPair(algorithm, { extractable: true });

    const publicJwk = await jose.exportJWK(keys.publicKey);

    const kid = v4();
    const pubJwk = { ...publicJwk, kid, alg: algorithm, use: "sig" };

    this.privateKey = keys.privateKey;
    this.privateKeyAlgoritm = algorithm;
    this.privateKeyKid = kid;
    this.publicKey = keys.publicKey;
    this.keyFunction = jose.createLocalJWKSet({ keys: [pubJwk] });
    return;
  }

  private async publicKeyInit(options: JWTWalletModuleModuleOptions) {
    if (options.issuer === undefined) {
      if (options.devPublicKey === undefined) {
        await this.generateKeys();
        if (options.devPort === undefined) {
          this.logger.warn(
            "Assuming testing. Using generated public/private keys"
          );
          return;
        }
        await this.saveKeys();

        return;
      }

      const publicKeyDecoded = JSON.parse(
        Buffer.from(options.devPublicKey, "base64").toString("utf8")
      ) as jose.JWK;

      this.keyFunction = jose.createLocalJWKSet({ keys: [publicKeyDecoded] });
      this.issuer =
        "http://localhost:" + (options.devPort ?? 8080).toString(10);
      this.logger.warn(`Using development JWKS: ${this.issuer}`);
      this.logger.warn(
        `Please do not use this in production. This will not be secure.`
      );
      return;
    }

    this.issuer = options.issuer;

    this.keyFunction = jose.createRemoteJWKSet(
      new URL(`${options.issuer}/.well-known/jwks.json`)
    );
    this.logger.log(`Using remote JWKS: ${this.issuer}`);
  }

  private async privateKeyInit(options: JWTWalletModuleModuleOptions) {
    if (options.privateKey !== undefined) {
      const privateJWK = JSON.parse(
        Buffer.from(options.privateKey, "base64").toString("utf8")
      ) as unknown;

      const kid =
        privateJWK !== null &&
        typeof privateJWK === "object" &&
        "kid" in privateJWK &&
        typeof privateJWK.kid === "string"
          ? privateJWK.kid
          : undefined;

      if (kid === undefined) {
        throw new KeyIdDidNotMatchError();
      }

      const algorithm = (privateJWK as jose.JWK).alg;

      if (algorithm === undefined) {
        throw new UndefinedAlgoritmError();
      }

      const key = (await jose.importJWK(
        privateJWK as jose.JWK,
        algorithm
      )) as webcrypto.CryptoKey;

      this.privateKey = key;
      this.privateKeyAlgoritm = algorithm;
      this.privateKeyKid = kid;

      this.logger.log(`Using private key with kid: ${kid}`);
      return;
    }

    this.logger.warn(
      "TokenService does not have a private key. And will not be able to sign tokens."
    );
  }

  private async saveKeys() {
    if (this.privateKey === undefined || this.privateKeyKid === undefined) {
      throw new KeyMissingError();
    }
    if (this.publicKey === undefined) {
      throw new KeyMissingError();
    }
    if (this.privateKeyAlgoritm === undefined) {
      throw new UndefinedAlgoritmError();
    }

    const privateJWK = await jose.exportJWK(this.privateKey);

    const privKey = Buffer.from(
      JSON.stringify({
        ...privateJWK,
        kid: this.privateKeyKid,
        alg: this.privateKeyAlgoritm,
        use: "sig"
      })
    ).toString("base64");

    const publicJwk = await jose.exportJWK(this.publicKey);

    const pubJwk = {
      ...publicJwk,
      kid: this.privateKeyKid,
      alg: this.privateKeyAlgoritm,
      use: "sig"
    };

    const pubKey = Buffer.from(JSON.stringify(pubJwk)).toString("base64");

    this.logger.error(
      `Please save this values to your .env.local file and restart the server\nJWT_PRIVATE=${privKey}\nJWT_MOCK_PUBLIC=${pubKey}`
    );

    throw new SaveTokenExitError();
  }

  public async signToken(object: jose.JWTPayload, expiresOn: number) {
    if (
      this.privateKey === undefined ||
      this.privateKeyKid === undefined ||
      this.privateKeyAlgoritm === undefined
    ) {
      this.logger.error("No private key provided");
      throw new PrivateKeyMissingError();
    }

    const audience =
      (Array.isArray(object.aud) ? object.aud[0] : object.aud) ??
      "Unknown Audience";

    this.logger.debug(
      `Signing ${audience} token #[${object.jti ?? ""}] for subject (${object.sub ?? ""}) with private key: ${this.privateKeyKid}`
    );
    const rootJwt = await new jose.SignJWT(object)
      .setExpirationTime(expiresOn)
      .setIssuer(this.issuer)
      .setIssuedAt()
      .setNotBefore("0s")
      .setProtectedHeader({
        alg: this.privateKeyAlgoritm,
        kid: this.privateKeyKid
      })
      .sign(this.privateKey);

    return rootJwt;
  }

  public async verifyToken(token: string, audience: string) {
    const { payload } = await jose.jwtVerify(token, this.keyFunction, {
      audience
    });

    return payload;
  }
}
